package main

// TODO: Known problems and bugs:
// TODO: 1. Setting current-context only works every other time - need to take into account all files read

import (
	"context"
	"flag"
	"fmt"
	"github.com/Bisnode/kubectl-login/handler"
	"github.com/Bisnode/kubectl-login/util"
	"github.com/dgrijalva/jwt-go"
	"github.com/skratchdot/open-golang/open"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const usageInstructions string = `Usage of kubectl login:
  --force
         Force re-authentication even if a valid token is present in config
  --init string
         Initialize kubeconf for provided environment (dev|qa|stage|prod) or "all" to initialize all environments
`

// Setup a 'clean' kubeconf file for the given environment
func initKubeConfContext(env string, clientCfg *api.Config, setCurrentCtx bool) {
	account := "blue"
	if env == "prod" {
		account = "orange"
	}
	ctx := fmt.Sprintf("tr.k8s.%v.%v.bisnode.net", env, account)

	clusterConf := map[string]*api.Cluster{ctx: {Server: "https://api." + ctx, InsecureSkipTLSVerify: true}}

	userConf := &api.AuthInfo{
		Exec: &api.ExecConfig{
			Command:    "kubectl-login",
			Args:       []string{"--print"},
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
	}
	contextConf := &api.Context{Cluster: ctx, AuthInfo: ctx}
	kubeconf := api.Config{
		Clusters:  clusterConf,
		AuthInfos: map[string]*api.AuthInfo{ctx: userConf},
		Contexts:  map[string]*api.Context{ctx: contextConf},
	}

	if clientCfg.CurrentContext == "" && setCurrentCtx {
		fmt.Printf("No current-context configured - using context %v\n", ctx)
		kubeconf.CurrentContext = ctx
	}

	kubeconfFile := clientcmd.RecommendedHomeFile + "." + env
	err := clientcmd.WriteToFile(kubeconf, kubeconfFile)
	if err != nil {
		log.Fatalf("Failed writing config to file %v", kubeconfFile)
	}

	fmt.Printf("Stored initial %v configuration in %v\n", env, kubeconfFile)
}

func parseArgs(clientCfg *api.Config) (forceLogin bool, execCredentialMode bool) {
	flag.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, usageInstructions)
	}
	init := flag.String("init", "", "")
	flag.BoolVar(&forceLogin, "force", false, "")
	flag.BoolVar(&execCredentialMode, "print", false, "")
	flag.Parse()

	if *init != "" {
		if *init != "all" {
			initKubeConfContext(*init, clientCfg, true)
		} else {
			for _, env := range []string{"dev", "qa", "stage", "prod"} {
				initKubeConfContext(env, clientCfg, env == "dev")
			}
		}
		os.Exit(0)
	}

	if flag.NArg() > 0 {
		_, _ = fmt.Fprint(os.Stderr, fmt.Sprintf("Unrecognized parameter(s): %v\n", flag.Args()))
		flag.Usage()
		os.Exit(1)
	}

	return forceLogin, execCredentialMode
}

func startServer(server *http.Server) {
	_ = server.ListenAndServe()
}

func main() {
	quitChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	cluster := api.NewCluster()
	cluster.InsecureSkipTLSVerify = true

	clientCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		log.Fatal("Failed to get default config")
	}
	forceLogin, execCredentialMode := parseArgs(clientCfg)

	if clientCfg.CurrentContext == "" {
		fmt.Println("No current-context set - run 'kubectl login --init' to initialize context")
		os.Exit(1)
	}

	currentToken := clientCfg.AuthInfos[clientCfg.CurrentContext].Token
	if currentToken != "" && !forceLogin {
		// We are only really interested in the expiry claim - all verification will be done by the kubernetes API
		parser := jwt.Parser{SkipClaimsValidation: true}
		claims := &jwt.StandardClaims{}
		_, _, err := parser.ParseUnverified(currentToken, claims)
		if err != nil {
			log.Println(err)
			log.Fatalf("Failed parsing claims from provided token: %v", currentToken)
		}

		exp := time.Unix(claims.ExpiresAt, 0)
		if time.Now().Before(exp) {
			if execCredentialMode {
				fmt.Println(fmt.Sprintf(util.ExecCredentialObject, currentToken, exp.Format(time.RFC3339)))
			} else {
				fmt.Println(
					"Previously fetched ID token still valid. Use kubectl login --force to force re-authentication.")
			}
			return
		}
	}

	issuer := util.ClusterIssuer(clientCfg.CurrentContext)
	authzEndpointURL, _ := url.Parse(issuer.AuthorizeEndpoint)
	_, err = net.LookupIP(authzEndpointURL.Host)
	if err != nil {
		fmt.Println(fmt.Sprintf("Could not resolve %v. Are you on the office network / VPN?", authzEndpointURL.Host))
		os.Exit(1)
	}

	nonce := util.RandomString(12)
	authorizeParameters := map[string]string{
		// Don't send ACR for now as this has caused problems on the SAML (ADFS) side. It _should_ work, but for now
		// just redirect straight to the ADFS authenticator instead.
		// "acr":           "urn:se:curity:authentication:html-form:adfs",
		"redirect_uri":  "http://localhost:16993/redirect",
		"client_id":     "kubectl-login",
		"response_type": "id_token",
		"response_mode": "form_post",
		"scope":         "profile openid",
		"nonce":         nonce,
	}
	authorizeRequestURL := issuer.AuthorizeEndpoint + "?"
	for k, v := range authorizeParameters {
		authorizeRequestURL += k + "=" + v + "&"
	}
	authorizeRequestURL = strings.TrimRight(authorizeRequestURL, "&")
	err = open.Run(authorizeRequestURL)
	if err != nil {
		log.Fatal(err)
	}

	idTokenHandler := &handler.IDTokenWebhookHandler{
		ClientCfg:          clientCfg,
		ForceLogin:         forceLogin,
		ExecCredentialMode: execCredentialMode,
		Nonce:              nonce,
		QuitChan:           quitChan,
	}
	server := &http.Server{
		Addr:           ":16993",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		Handler:        idTokenHandler,
	}

	go startServer(server)
	for {
		select {
		case <-idTokenHandler.QuitChan:
			ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
			_ = server.Shutdown(ctx)
			return
		case <-sigChan:
			close(quitChan)
		default:
		}
	}
}
