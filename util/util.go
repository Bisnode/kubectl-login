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

	"github.com/golang-jwt/jwt"
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
	if claims.Groups == nil {
		log.Print("Claim \"groups\" missing from ID token")
		return make([]string, 0)
	}

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

// ClusterCaCert provides the CA cert for the given cluster, or "unknown" if not in map of known clusters
func ClusterCaCert(context string) string {
	//goland:noinspection SpellCheckingInspection
	clusterCaCerts := map[string]string{
		"tr.k8s.dev.blue.bisnode.net": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWJ1Z0F3SUJBZ0lNRjFWN1BFL092R" +
			"EpHNERrTE1BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1qTXdOREV4TVRFek1qR" +
			"TBXaGNOTXpNd05ERXdNVEV6TWpFMApXakFWTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1JSUJJakFOQmdrcWhraUc5dzBCQVFFR" +
			"kFBT0NBUThBCk1JSUJDZ0tDQVFFQW5zV3Y5WmgveTJpMEpyTjdZS2V6K2xzZWJpN0hGZkxSWUx5di9mbkdxTDR0eGFhUXRkamEKc0hae" +
			"S9zVVRWVitwajdsMUZxQVRDSFo0ZjIyZGcySHVYVEU1YWJ0azQzZE9Rc2FtaUo2aDNRMlJCbEp2ZVU3LwpHZ0hYcXI2SHFRNHFIdnl6Q" +
			"VZ4Wk1ZMmk5MTA5K0R0ejh1TmVRZWtteHgrZjcvMnIzL3lFV2FEQ1ZWSHlOTnd6CmRYalZGUmpIVzFlZTFzbTM0YjExcDRIN0F5WDZZc" +
			"jN2dlFQQVpqNHhQMm1HTVlxVFAwRzRnL2JaL2QzZ2JXWDIKTmlObXpRLzMzYlgrTmQ3NjUwdE82NXU5dFF1alA2dGZHYjN1d1ZKYUVXR" +
			"UtPZWFkUEtMZlR6MG42T1pEbWVTSQo2Y1ljRWw1V2wxYWFnb3c1UExWSTROTkNtZHJpSWpkOWR3SURBUUFCb3lNd0lUQU9CZ05WSFE4Q" +
			"kFmOEVCQU1DCkFRWXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFaZElDb01Qc3VwY0UKQnZYd" +
			"GhxbS9uY3VSVmlKRXVlTFZPcHBsMmw0emhITjd1aS9nMkE3STJzVjF6alhzSXZlZ0JDZE9EaEhVaU5OUAo1dVZ2M3BLRkRJWmFaM0I3L" +
			"0FiZW1rOTByN01Wc1FxWi9pRGRURmV6dFowU1F3U0ppODlaY2RkdC9oTjFYdVFaCmxWSlMvMDRGUzBZYzJYOUFic28vRG1ObkloTUlqb" +
			"TNyejlLZkNmNUFpMzFVTnF4cGZKekM0eU9IbjVUdkg4dE0KWVhGbm4rL3RoWjJtZTVyYytOM2F1b3hUQ0w4RksrZTQzY3A0RXU2enJkd" +
			"W5EWUg1U3NKejlNeHlTclNsOVYwVQptZWIwdUxXT0xUclZzczBvNSs5Wkk3Q2J1Z3cwalpqTENRNHRoWkRuSWlIalV2WkVtWEl4SkdZU" +
			"zA3UERGUXhrCm1SUmxuVFVhWlE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
		"tr.k8s.qa.blue.bisnode.net": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWJ1Z0F3SUJBZ0lNRlZwVXRIVjk1Z0" +
			"VXSjJybk1BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1UZ3hNREF5TURZME1qTT" +
			"JXaGNOTWpneE1EQXhNRFkwTWpNMgpXakFWTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1JSUJJakFOQmdrcWhraUc5dzBCQVFFRk" +
			"FBT0NBUThBCk1JSUJDZ0tDQVFFQTIrZTdlTlVhWHlsek92QzgvTnZGVGVROFo1aVNFS2p6V3owMnB4d2YySVluR2Y3byt6SEIKMFh0cz" +
			"VORFFiZTdzUGdsUFJ2eDBnZWNuTGdRWVhWc1poZVludG9jb3g5RDlXQnQ1aXIvM3RZcEVOOGxiUzRkSwpBdWRPdmlqM05vblpDWW4wNG" +
			"FhanVsRUFxOVREaHdRNEdUbUpiTTFFRUJiTEUrVjVNenV0REF6Y0x3aTJOeVFlCmVEa3dmK2pWemFiOWNyUy8wTDdOcVpLME1YUWUvTG" +
			"NKVm5zbHNCQ1FZKzVvdC9yeHNNVVh6RTlCaGhoN3k1b3EKT0FEbHZFUzFueFNuZnIvOURlSytDcDZUUmZFUGhYTnM3dzJrOVVGYzd3c2" +
			"l0dVZ0RTRGSDY3Nzh5RFJ0a29wKwowMFIrL25jWW1vVTBWSlVrVS9XZzNzelBxazdtOFV0cklRSURBUUFCb3lNd0lUQU9CZ05WSFE4Qk" +
			"FmOEVCQU1DCkFRWXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFSaThWQ09Vanord2kKWEFLTF" +
			"lsMVZlMWdwZWpqc3RTZ3JUSEZ6aWpvNmFyeGNIbW1DaWFCQWU5dkVkaFZrbWt0N0x0aU1Dd2xNdFpUcQpPdGFlNEZzT25PREJHeG5HT2" +
			"l0NzkxSnBhZ2lzZ2NFTFpHbEIvNlArSHkybVdPcEZ2L29aNGdxTWNJVzdNSDZzCmg2cjhUNEtLNmIwSWFuaFR6SlhSZEJtY3pWRGNKdH" +
			"pVRmpwUERTZ1VFaHlTL0RVZzhnTjV3dEp4SEFsTEtoWjgKYVA0K1pUQnRMc2JpN0FLeWt4T3FaQmFMa0JGMjRScitTM3lXcVJLd0dDRn" +
			"hxaHNHQi90N2RBQkNBU3ZUSnlDLwpFMU5oRUQyL3VSdklpWUUwUmloR1EwWGo0N2NscGhWcGtxYTg1SFo2aTdDbFpoN3hHOFZsTGhYdE" +
			"5BRTdTNjBUCmt0VFVEUVJ3SWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
		"tr.k8s.stage.blue.bisnode.net": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWJ1Z0F3SUJBZ0lNRlZxb2s4K1J" +
			"ZSExRUklWUU1BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1UZ3hNREF6TURneE9" +
			"UTTFXaGNOTWpneE1EQXlNRGd4T1RNMQpXakFWTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1JSUJJakFOQmdrcWhraUc5dzBCQVF" +
			"FRkFBT0NBUThBCk1JSUJDZ0tDQVFFQXJEQmZhVmRzbys3Qk9EOTk5SlFGN081SDBObTRBMEp2dUxLVzBDNTN6Q05Zd1ljalFkaE4KdFg" +
			"wQlJpbmxQSjBmSmF5VEtEYml2VmZmbzhLRTcycVZUbExCZUpkSUwxVGNITkZKcEpMak1rUzJVM0hjUThSVQpMeUU2aHNxNVR1Zkk4MTR" +
			"sMGpWL2VSSHBZa3FqcXkrRkNDU2dKY2s2VGkrVHNIanRMUHBGUmE2cXJMSHp0RHFWCjdZM28xblFTYU9NK3BKYjc2eU1ya0NYNHQ0R1R" +
			"6NlVGaUJIT2xrVDk2V1RsU3Y3VzBBUUFwc3Z4VnR1SmlyY1AKeXlGNVdxTkVrSXpTbEV0SjRzMGJuWUxQcy9SRjl4ZzNzYThyOEs2TWp" +
			"yTFhvNlBVajcyZFFvb2tIRFBMVVJZSQpoWnYyTGlQdG1LOEJCRi9BZ1dqTlpEVGFpMDZRQTd5ZjlRSURBUUFCb3lNd0lUQU9CZ05WSFE" +
			"4QkFmOEVCQU1DCkFRWXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFBYkNyd1lXcVBDd1IKcFl" +
			"1eXB3VW0yWWpXOW1aK21PM083Z0wzK1F2eG1PYmVqU0tiQUlaV3pNNG14ZTZVMDdMekZ3TDdnOEpIU0YxeApYakRQRUJHOGdQSmlDelB" +
			"4SnpyZ1U0NFBUMjYwZmZMSkF3RlV1K1lCd1Juc2NNZ1J5NWR2UEN2cjlBeVhIWG01CndEdzhoUWl2bGt2ZFVBSm5YUXU2YWxJT1BvVXF" +
			"zanIyMGpZL29DVGI3Sm1oMStIeER0WmRFU2wvWmZSb3lmUEgKc3BZV1RoSzkxZEJkdFg1QTRrclZKaDNFQW1ZaGhQVkxNcDZyVTdOUG9" +
			"JTVNtQ2VoVHJyY05XaEU4ZjBwVFVTOQp4ZW1jUnQwVUxwSWlRQ3kxK1Yya25tYmRxYmJxUVlhUGZ6NXpZc3hmdTVSdU1zeWQxUWNvMDR" +
			"0UU5XWnhFQjF5Ckcxd0JNSUgvZFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
		"tr.k8s.prod.orange.bisnode.net": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWJ1Z0F3SUJBZ0lNRlZxMnlKeT" +
			"kyOEF6cnlMS01BMEdDU3FHU0liM0RRRUJDd1VBTUJVeEV6QVIKQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13SGhjTk1UZ3hNREF6TVRJek" +
			"9UVTFXaGNOTWpneE1EQXlNVEl6T1RVMQpXakFWTVJNd0VRWURWUVFERXdwcmRXSmxjbTVsZEdWek1JSUJJakFOQmdrcWhraUc5dzBCQV" +
			"FFRkFBT0NBUThBCk1JSUJDZ0tDQVFFQXlGYUlTaWl5ekdBWmFkZXhMelZzdjNwZ2hRQmh4TUtyd0RNaTZ5WkNqY0JHWkF1NEVRWXgKa0" +
			"pyV2ZPaHhXUUM4Z3dEckZCTTF3dUtoRlVESDFOOXIzQm04TDN5N3R5QjM3aEx3ZG5hK09JYjlKWDk5a3N5bwpINEpmOWk3Ukh1UzFwYT" +
			"VUaXpuR05IL2xNRU90dGpDTTlIb0pYcWpSZ2NjS1B4SCs2RUczaU1jUHdlWTU2L1pYCkFZOTNxdnlMSXE1bTlUVVZlM3NxS3FYTTBUaW" +
			"9ZNmxNdmVaY0dYVXVFd3N4dkJZU3RDRTM2N2FYd3J4aWRORnQKUGpYQlF3YklHcGg3MUF1RmMzMHE1SnFxTmVkYTdEcXNSbzJYUXpDTn" +
			"Z3c1U3R2lTSDNKbGc0YmlRRDZKelQwLwpYa2hrbDQ3b0tJRXovV0I1bmhSNVZLUG9zWkVvYVd1NFFRSURBUUFCb3lNd0lUQU9CZ05WSF" +
			"E4QkFmOEVCQU1DCkFRWXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUF2dFB0OE5vNGtXbVkKeX" +
			"JqRDdqVndnRDc1SDJQR1Q0WjltbG9TV05NVEdsc3lIMFE2TXBXVHFlaTdyQkQ1TFZ0Vzh0dEdWNFVFd25PRwpXeVJMMFMvZHRBY3J1Uk" +
			"xXYnJWaUEvUU5kN1BHZ2dlQXRJSkZBQk11QStGaG1qV1A5cmVocnBmYVZMWjU5NDNiCndhUWg5Ky9FV2czdEE2VTgwREZzMGsra0U0WD" +
			"JTcWdaVUlMRk9GVXJjdWFKR1FQNUhaQ0JQMGlzQkJtbFNCeDcKRGIvRllVZUlVemRrWjdXZ0RCbDcwd3ByM0Z4NEJmb1daUHRPWG9oSn" +
			"FUOWtuZU85eS9ZdVYzUlArMTVSYUNudwpNYmpxQTdveFliZ2hMSHdLM1BmYlhkR2RZbkhZNldHR3paZWY0b2hTNlBPeUJaanN0c01RSD" +
			"RHMFJhcjZGRkFQCmtMVXdGeWtwbUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
	}
	if val, ok := clusterCaCerts[context]; ok {
		return val
	}
	return "unknown"
}
