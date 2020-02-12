package util

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

// Issuer is the name / authorize endpoint mapping for our Common Login environments
type Issuer struct {
	Name              string
	AuthorizeEndpoint string
}

// IdentityClaims - token claims of interest for our use case
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

var (
	configDir = filepath.Join(clientcmd.RecommendedConfigDir, "kubectl-login")
)

// ExtractTeams returns all teams from groups as found in ID token
func ExtractTeams(claims *IdentityClaims) (teams []string) {
	for _, g := range *claims.Groups {
		group := strings.ToLower(g)
		if strings.HasPrefix(group, "sec-tbac-team-") {
			teams = append(teams, strings.TrimPrefix(group, "sec-tbac-"))
		}
	}
	return teams
}

// Whoami prints username, groups and team membership
func Whoami(user string, groups []string, teams []string) string {
	output := fmt.Sprintf("username: %v\n", user)
	output += fmt.Sprintf("groups: [\n%v]\n", Join(groups, "  ", ",\n"))

	teamBelonging := fmt.Sprintf("Determined team belonging: %v", Join(teams, "", ", "))
	output += fmt.Sprintf("%v\n", strings.Repeat("-", len(teamBelonging)))
	output += teamBelonging

	return output
}

// JwtToIdentityClaims retrieves user info (name and group belongings) from stored token
func JwtToIdentityClaims(rawToken string) *IdentityClaims {
	parser := &jwt.Parser{}
	claims := &IdentityClaims{}

	_, _, err := parser.ParseUnverified(rawToken, claims)
	if err != nil {
		log.Fatalf("Failed parsing token: %v, error: %v", rawToken, err)
	}

	return claims
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

// ClusterIssuer provides relevant issuer details given a context
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

// LoadConfigFromContext loads config object for provided context
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

// WriteToken writes token to ~/.kube/kubectl-login/${env}/token.jwt
func WriteToken(token string, context string) error {
	dir := filepath.Join(configDir, ContextToEnv(context))
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(dir, "token.jwt"), []byte(token), 0644)
	if err != nil {
		return err
	}
	return nil
}

// ReadToken returns token or empty string if missing or failure to read it (likely due to it not being written yet)
func ReadToken(context string) string {
	dir := filepath.Join(configDir, ContextToEnv(context))
	bytes, err := ioutil.ReadFile(filepath.Join(dir, "token.jwt"))
	if err != nil {
		return ""
	}
	return string(bytes)
}
