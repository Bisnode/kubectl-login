package util

import (
	"log"
	"math/rand"
	"strings"
	"time"
)

// Issuer is the name / authorize endpoint mapping for our Common Login environments
type Issuer struct {
	Name              string
	AuthorizeEndpoint string
}

// ExecCredentialObject - when run as a an exec credential plugin - which is the common mode of operation, the output
// is printed to stdout and captured by kubectl who will know what to do with the token
const ExecCredentialObject = `{
	"apiVersion": "client.authentication.k8s.io/v1beta1",
	"kind": "ExecCredential",
	"status": {
		"token": "%v",
		"expirationTimestamp": "%v"
	}
}`

// RandomString returns a semi-random string of variable length
func RandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func ClusterIssuer(context string) Issuer {
	clusterIssuers := map[string]Issuer{
		"tr.k8s.dev.blue.bisnode.net": {
			Name:              "https://dev-login.bisnode.com",
			AuthorizeEndpoint: "https://dev-login.bisnode.com/as/authorization.oauth2",
		},
		"tr.k8s.qa.blue.bisnode.net": {
			Name:              "https://qa-login.bisnode.com",
			AuthorizeEndpoint: "https://qa-login.bisnode.com/as/authorization.oauth2",
		},
		"tr.k8s.stage.blue.bisnode.net": {
			Name:              "https://stage-login.bisnode.com",
			AuthorizeEndpoint: "https://stage-login.bisnode.com/as/authorization.oauth2",
		},
		"tr.k8s.prod.orange.bisnode.net": {
			Name:              "https://login.bisnode.com",
			AuthorizeEndpoint: "https://login.bisnode.com/as/authorization.oauth2",
		},
	}
	if val, ok := clusterIssuers[context]; ok {
		return val
	}
	return clusterIssuers["tr.k8s.dev.blue.bisnode.net"]
}

// ContextToEnv translates any known context to it's corresponding environment, or dev if not found
func ContextToEnv(context string) (env string) {
	ctxEnvMap := map[string]string{
		"tr.k8s.lab.blue.bisnode.net":    "lab",
		"tr2.k8s.lab.blue.bisnode.net":   "lab2",
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

// Join with both prefix and suffix
func Join(items []string, prefix, suffix string) string {
	if len(items) == 1 {
		return items[0]
	}
	joined := ""
	for _, item := range items {
		joined += prefix + item + suffix
	}
	return joined
}
