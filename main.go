package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Bisnode/kubectl-login/handler"
	"github.com/Bisnode/kubectl-login/util"
	"github.com/golang-jwt/jwt"
	"github.com/skratchdot/open-golang/open"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const version = "1.0.0"

const usageInstructions string = `Usage of kubectl login:
  --force
         Force re-authentication even if a valid token is present in config
  --init string
         Initialize kubeconf for provided environment (dev|qa|stage|prod) or "all" to initialize all environments
  whoami
		 Print details of the current authenticated user (like group membership)
  version
		 Print current version and exit
`

// Setup a 'clean' kubeconf file for the given environment
func initKubeConfContext(env string, clientCfg *api.Config, setCurrentCtx bool) {
	account := "blue"
	if env == "prod" {
		account = "orange"
	}
	ctx := fmt.Sprintf("tr.k8s.%v.%v.bisnode.net", env, account)

	clusterConf := map[string]*api.Cluster{ctx: {Server: "https://api." + ctx}}

	caCert := util.ClusterCaCert(ctx)
	if caCert == "unknown" {
		fmt.Printf("Unkown cluster %v, will skip TLS verification", ctx)
		clusterConf[ctx].InsecureSkipTLSVerify = true
	} else {
		bytes, err := base64.StdEncoding.DecodeString(caCert)
		if err != nil {
			log.Fatalf("Failed to decode CA certificate for cluster %v", ctx)
		}
		clusterConf[ctx].CertificateAuthorityData = bytes
	}

	userConf := &api.AuthInfo{
		Exec: &api.ExecConfig{
			Command:    "kubectl-login",
			Args:       []string{"--print", "--context=" + ctx},
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

func parseArgs(clientCfg *api.Config) (forceLogin bool, execCredentialMode bool, ctx string) {
	flag.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, usageInstructions)
	}
	init := flag.String("init", "", "")
	flag.StringVar(&ctx, "context", "", "")
	flag.BoolVar(&forceLogin, "force", false, "")
	flag.BoolVar(&execCredentialMode, "print", false, "")
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		os.Exit(0)
	}

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

	if flag.NArg() > 0 && flag.Arg(0) == "whoami" {
		rawToken := currentToken(clientCfg)
		if rawToken == "" {
			fmt.Println("No token found in storage - make sure to first login")
			os.Exit(1)
		}
		claims := util.JwtToIdentityClaims(rawToken)
		fmt.Println(util.Whoami(claims.Username, *claims.Groups, util.ExtractTeams(claims)))
		os.Exit(0)
	}

	if flag.NArg() > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Unrecognized parameter(s): %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	return forceLogin, execCredentialMode, ctx
}

func startServer(server *http.Server) {
	_ = server.ListenAndServe()
}

func currentToken(clientCfg *api.Config) string {
	if clientCfg.CurrentContext == "" {
		log.Println("No current-context set - run 'kubectl login --init' to initialize context")
		os.Exit(1)
	}
	// Note that absence of a token is not an error here but an empty string is returned
	return util.ReadToken(clientCfg.CurrentContext)
}

func main() {
	quitChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	timeoutChan := make(chan bool, 1)
	go func() {
		time.Sleep(10 * time.Minute)
		timeoutChan <- true
	}()

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	cluster := api.NewCluster()
	cluster.InsecureSkipTLSVerify = true

	clientCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		log.Fatal("Failed to get default config")
	}
	forceLogin, execCredentialMode, execCredentialCtx := parseArgs(clientCfg)

	// Special handling of "execCredentialContext" - this is basically hit when doing
	// kubectl get whatever --context=some-context
	// where "some-context" is not the _current context_.
	if execCredentialMode && execCredentialCtx != clientCfg.CurrentContext {
		clientCfg = util.LoadConfigFromContext(execCredentialCtx)
		clientCfg.CurrentContext = execCredentialCtx
	}

	currentToken := currentToken(clientCfg)
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
		log.Fatalf("Could not resolve %v. Are you on the office network / VPN?", authzEndpointURL.Host)
	}

	nonce := util.RandomString(12)
	authorizeParameters := map[string]string{
		// Don't send ACR for now as this has caused problems on the SAML (ADFS) side. It _should_ work, but for now
		// just redirect straight to the ADFS authenticator instead.
		// "acr":           "urn:se:curity:authentication:html-form:adfs",
		"redirect_uri":  "http://127.0.0.1:16993/redirect",
		"client_id":     "kubectl-login",
		"response_type": "id_token",
		"response_mode": "form_post",
		"scope":         "openid%20email%20tbac",
		"nonce":         nonce,
	}
	authorizeRequestURL := issuer.AuthorizeEndpoint + "?"
	for k, v := range authorizeParameters {
		authorizeRequestURL += k + "=" + v + "&"
	}
	authorizeRequestURL = strings.TrimRight(authorizeRequestURL, "&")

	preferredBrowser := os.Getenv("KUBECTL_LOGIN_BROWSER")
	if preferredBrowser == "" {
		// Open with system browser
		err = open.Run(authorizeRequestURL)
	} else {
		// Note case sensitivity - "Google Chrome", "Safari", etc
		err = open.RunWith(authorizeRequestURL, preferredBrowser)
	}
	if err != nil {
		log.Fatalf("Failed opening web browser: %v", err)
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
		case <-timeoutChan:
			log.Fatal("kubetcl-login aborting after idling for 10 minutes")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}
