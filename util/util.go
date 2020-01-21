package util

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
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

type IdentityClaims struct {
	Username string    `json:"email"`
	Groups   *[]string `json:"groups"`
	jwt.StandardClaims
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

// Retrieve user info (name and group belongings) from stored token
func Whoami(rawToken string) string {
	if rawToken == "" {
		return "No token found in storage - make sure to first login"
	}

	parser := &jwt.Parser{}
	claims := &IdentityClaims{}

	_, _, err := parser.ParseUnverified(rawToken, claims)
	if err != nil {
		log.Fatalf("Failed parsing token: %v", rawToken)
	}

	var teams []string
	for _, g := range *claims.Groups {
		group := strings.ToLower(g)
		if strings.HasPrefix(group, "sec-team-") {
			teams = append(teams, strings.TrimLeft(group, "sec-"))
		}
	}

	output := fmt.Sprintf("username: %v\n", claims.Username)
	output += fmt.Sprintf("groups: [\n%v]\n", Join(*claims.Groups, "  ", ",\n"))

	teamBelonging := fmt.Sprintf("Determined team belonging: %v", Join(teams, "", ", "))
	output += fmt.Sprintf("%v\n", strings.Repeat("-", len(teamBelonging)))
	output += teamBelonging

	return output
}

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

func LoadConfigFromContext(context string) *api.Config {
	file := clientcmd.RecommendedHomeFile + "." + ContextToEnv(context)
	conf, err := clientcmd.LoadFromFile(file)
	if err != nil {
		log.Fatalf("Failed reading file %v", file)
	}
	return conf
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
