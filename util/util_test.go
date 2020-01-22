package util

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"reflect"
	"testing"
)

func TestExtractsSingleTeamFromListOfGroups(t *testing.T) {
	token := issueTestToken("bobby@bisnode.com", []string{
		"sec-team-ignored",
		"sec-tbac-team-cool-runners",
		"team-also-ignored",
		"definitely-ignored",
	})
	claims := JwtToIdentityClaims(token)
	teams := ExtractTeams(claims)

	expected := []string{"team-cool-runners"}

	if !reflect.DeepEqual(expected, teams) {
		t.Errorf("Expected teams to be %v but was %v", expected, teams)
	}
}

func TestExtractsMultipleTeamsFromListOfGroups(t *testing.T) {
	token := issueTestToken("bobby@bisnode.com", []string{
		"sec-team-not-gonna-count",
		"sec-tbac-team-vip-treatment",
		"team-also-not-gonna-count",
		"sec-tbac-team-lunatics",
		"definitely-not-gonna-count",
	})
	claims := JwtToIdentityClaims(token)
	teams := ExtractTeams(claims)

	expected := []string{"team-vip-treatment", "team-lunatics"}

	if !reflect.DeepEqual(expected, teams) {
		t.Errorf("Expected teams to be %v but was %v", expected, teams)
	}
}

func issueTestToken(user string, groups []string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":  user,
		"groups": groups,
	})

	signature := "much-valid-signature-ffs"

	tokenEncoded, err := token.SignedString([]byte(signature))
	if err != nil {
		fmt.Println(err)
	}

	return tokenEncoded
}
