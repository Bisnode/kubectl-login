package handler

import (
	"fmt"
	"github.com/Bisnode/kubectl-login/util"
	"github.com/dgrijalva/jwt-go"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"log"
	"net/http"
	"time"
)

// IDTokenWebhookHandler carries configuration and any other state (like the nonce) between the main initialization and
// the subsequent fetching of the ID token passed to the server after authenticating.
type IDTokenWebhookHandler struct {
	ClientCfg          *api.Config
	ForceLogin         bool
	ExecCredentialMode bool
	Nonce              string
	QuitChan           chan struct{}
}

// StdClaimsWithNonce - since all verification is done server side by the kubernetes API, all we are really interested
// in here is that:
// 1) the token is not expired or else we shouldn't store it and
// 2) that the nonce in the ID token is the same as that provided in the authorization request
type StdClaimsWithNonce struct {
	Nonce string `json:"nonce"`
	jwt.StandardClaims
}

func badRequest(w http.ResponseWriter, message string) {
	log.Println(message)
	w.WriteHeader(http.StatusBadRequest)
	log.Print(fmt.Fprintf(w, message))
}

// Extract ID token from form POST parameter and send 200 OK response
func (h *IDTokenWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		log.Print(fmt.Fprintf(w, ""))
		return
	}

	if r.URL.Path != "/redirect" {
		log.Println("POST request received to other endpoint than /redirect. Skipping.")
		return
	}

	if r.Header.Get("Content-Length") == "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		badRequest(w, "Content-Length or Content-Type not provided or invalid")
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Println("Unable to parse form body")
		return
	}

	idToken := r.PostForm.Get("id_token")
	if idToken == "" {
		badRequest(w, "No id_token provided in request. Aborting.")
		return
	}

	parser := &jwt.Parser{}
	claims := &StdClaimsWithNonce{}
	token, _, err := parser.ParseUnverified(idToken, claims)
	if err != nil {
		log.Printf("Failed decoding claims %s", err)
		return
	}

	if claims.Nonce != h.Nonce {
		log.Fatal("Nonce in ID token not identical to that in authorization request. Aborting.")
	}

	exp := time.Unix(claims.ExpiresAt, 0)
	// Print the results if run as an exec credential plugin
	if h.ExecCredentialMode {
		fmt.Println(fmt.Sprintf(util.ExecCredentialObject, token.Raw, exp.Format(time.RFC3339)))
	}

	// Store in kubeconf regardless of mode
	currentCtx := h.ClientCfg.CurrentContext
	file := clientcmd.RecommendedHomeFile + "." + util.ContextToEnv(currentCtx)
	fileConf, err := clientcmd.LoadFromFile(file)
	if err != nil {
		log.Fatalf("Failed reading file %v", file)
	}
	fileConf.AuthInfos[currentCtx].Token = token.Raw
	err = clientcmd.WriteToFile(*fileConf, file)
	if err != nil {
		log.Fatalf("Failed writing token to file %v", file)
	}

	if !h.ExecCredentialMode {
		fmt.Println(fmt.Sprintf("Authenticated for context %v. Token valid until %v.", currentCtx, exp))
	}

	// Return control to shell at this point
	h.QuitChan <- struct{}{}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)
	_, _ = w.Write([]byte("Authentication complete. You may close this browser tab."))
}
