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

func (auth *KeyCloakMiddleware) extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (auth *KeyCloakMiddleware) VerifyToken(next http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			msg := "Authorization header missing"
			http.Error(w, msg, http.StatusUnauthorized)
			log.Print(msg)
			return
		}

		token = auth.extractBearerToken(token)

		if token == "" {
			msg := "Bearer Token missing"
			http.Error(w, msg, http.StatusUnauthorized)
			log.Print(msg)
			return
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
