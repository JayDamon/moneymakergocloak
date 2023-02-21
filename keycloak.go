package moneymakergocloak

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v12"
)

type Middleware struct {
	KeyCloakConfig *Configuration
}

type Configuration struct {
	GoCloak      *gocloak.GoCloak
	ClientId     string
	ClientSecret string
	Realm        string
	DebugActive  bool
}

func NewMiddleWare(config *Configuration) *Middleware {
	return &Middleware{KeyCloakConfig: config}
}

func NewConfiguration() *Configuration {

	issuerUri := getOrDefault("ISSUER_URI", "http://keycloak:8081/auth")
	clientId := getOrDefault("CLIENT_NAME", "account-link-service-service")
	clientSecret := getOrDefault("CLIENT_SECRET", "wQeV8pZwtBf9dIdKTGrqceyM3eeleokY")
	realm := getOrDefault("REALM", "moneymaker")
	debugActive := getOrDefaultBool("DEBUG_ACTIVE", false)

	return &Configuration{
		GoCloak:      gocloak.NewClient(issuerUri),
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Realm:        realm,
		DebugActive:  debugActive,
	}
}

func (auth *Middleware) VerifyToken(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {

		token, err := extractTokenFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err.Error())
		}

		goCloakConfig := auth.KeyCloakConfig
		goCloak := goCloakConfig.GoCloak
		goCloak.RestyClient().SetDebug(auth.KeyCloakConfig.DebugActive)

		result, err := goCloak.RetrospectToken(context.Background(), token, goCloakConfig.ClientId, goCloakConfig.ClientSecret, goCloakConfig.Realm)
		if err != nil {
			msg := fmt.Sprintf("Invalid or malformed token: %s", err.Error())
			http.Error(w, msg, http.StatusUnauthorized)
			log.Print(msg)
			return
		}

		if !*result.Active {
			http.Error(w, "Invalid or expired Token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(f)
}

func ExtractUserIdFromToken(w http.ResponseWriter, r *http.Request, keyCloakConfig *Configuration) string {
	token, err := extractTokenFromRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}

	goCloak := keyCloakConfig.GoCloak
	_, claims, err := goCloak.DecodeAccessToken(context.Background(), token, keyCloakConfig.Realm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}

	id := (*claims)["sub"]

	return fmt.Sprintf("%v", id)
}

func extractTokenFromRequest(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	token = extractBearerToken(token)

	if token == "" {
		return "", fmt.Errorf("bearer Token missing")
	}

	return token, nil
}

func extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func getOrDefault(envVar string, defaultVal string) string {
	val := os.Getenv(envVar)
	if val == "" {
		return defaultVal
	}
	return val
}

func getOrDefaultBool(envVar string, defaultVal bool) bool {
	val := os.Getenv(envVar)
	var returnVal = defaultVal
	if val == "true" {
		returnVal = true
	} else if val == "false" {
		returnVal = false
	}

	return returnVal
}
