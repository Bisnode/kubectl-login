package util

import (
	"log"
	"math/rand"
	"strings"
	"time"
)

type Issuer struct {
	Name              string
	AuthorizeEndpoint string
}

const ExecCredentialObject = `{
	"apiVersion": "client.authentication.k8s.io/v1beta1",
	"kind": "ExecCredential",
	"status": {
		"token": "%v",
		"expirationTimestamp": "%v"
	}
}`

func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

// Providing also the authorize URL instead of getting it from the discovery endpoint is a workaround since we can't
// rely on PingFederate's authorize endpoint - instead we go straight to Curity
func ClusterIssuer(context string) Issuer {
	clusterIssuers := map[string]Issuer{
		"tr.k8s.dev.blue.bisnode.net": {
			Name:              "https://dev-id.bisnode.com:9031",
			AuthorizeEndpoint: "https://dev-login.bisnode.com/identityservice/internal/authn/authenticate",
		},
		"tr.k8s.qa.blue.bisnode.net": {
			Name:              "https://qa-id.bisnode.com:9031",
			AuthorizeEndpoint: "https://qa-login.bisnode.com/identityservice/internal/authn/authenticate",
		},
		"tr.k8s.stage.blue.bisnode.net": {
			Name:              "https://stage-id.bisnode.com:9031",
			AuthorizeEndpoint: "https://stage-login.bisnode.com/identityservice/internal/authn/authenticate",
		},
		"tr.k8s.prod.orange.bisnode.net": {
			Name:              "https://id.bisnode.com:9031",
			AuthorizeEndpoint: "https://login.bisnode.com/identityservice/internal/authn/authenticate",
		},
	}
	if val, ok := clusterIssuers[context]; ok {
		return val
	}
	return clusterIssuers["tr.k8s.dev.blue.bisnode.net"]
}

func ContextToEnv(context string) (env string) {
	ctxEnvMap := map[string]string{
		"tr.k8s.dev.blue.bisnode.net":    "dev",
		"tr.k8s.qa.blue.bisnode.net":     "qa",
		"tr.k8s.stage.blue.bisnode.net":  "stage",
		"tr.k8s.prod.orange.bisnode.net": "prod",
	}
	if val, ok := ctxEnvMap[context]; ok {
		return val
	}
	log.Printf("Can't translate context '%v' to env (dev|qa|stage|prod), defaulting to 'dev'", context)
	return "dev"
}
