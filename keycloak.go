package moneymakergocloak

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v12"
)

type KeyCloakMiddleware struct {
	KeyCloakConfig *KeyCloakConfig
}

type KeyCloakConfig struct {
	GoCloak      *gocloak.GoCloak
	ClientId     string
	ClientSecret string
	Realm        string
}

func NewKeyCloakMiddleWare(config *KeyCloakConfig) *KeyCloakMiddleware {
	return &KeyCloakMiddleware{KeyCloakConfig: config}
}

func NewKeyCloak(issuerUri string, clientId string, clientSecret string, realm string) *KeyCloakConfig {
	return &KeyCloakConfig{
		GoCloak:      gocloak.NewClient(issuerUri),
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Realm:        realm,
	}
}

func (auth *KeyCloakMiddleware) VerifyToken(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {

		token, err := extractTokenFromReqeust(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err.Error())
		}

		goCloakConfig := auth.KeyCloakConfig
		goCloak := goCloakConfig.GoCloak
		goCloak.RestyClient().SetDebug(true)

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

func ExtractUserIdFromToken(w http.ResponseWriter, r *http.Request, keyCloakConfig *KeyCloakConfig) string {
	token, err := extractTokenFromReqeust(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}

	gocloak := keyCloakConfig.GoCloak
	_, claims, err := gocloak.DecodeAccessToken(context.Background(), token, keyCloakConfig.Realm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Print(err.Error())
	}

	id := (*claims)["sub"]

	return fmt.Sprintf("%v", id)
}

func extractTokenFromReqeust(w http.ResponseWriter, r *http.Request) (string, error) {
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
