package moneymakergocloak

import (
	"context"
	"fmt"
	"github.com/rabbitmq/amqp091-go"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v12"
)

type KeycloakMiddleware struct {
	KeyCloakConfig *Configuration
}

type Configuration struct {
	GoCloak      *gocloak.GoCloak
	ClientId     string
	ClientSecret string
	Realm        string
	DebugActive  bool
}

type Middleware interface {
	AuthorizeMessage(msg *amqp091.Delivery) error
	AuthorizeHttpRequest(request http.Handler) http.Handler
	ExtractUserIdFromToken(token *string) (string, error)
}

func NewMiddleWare(config *Configuration) Middleware {
	return &KeycloakMiddleware{KeyCloakConfig: config}
}

func NewConfiguration() *Configuration {

	issuerUri := getOrDefault("ISSUER_URI", "http://keycloak:8081/auth")
	clientId := getOrFail("CLIENT_NAME")
	clientSecret := getOrFail("CLIENT_SECRET")
	realm := getOrFail("REALM")
	debugActive := getOrDefaultBool("DEBUG_ACTIVE", false)

	return &Configuration{
		GoCloak:      gocloak.NewClient(issuerUri),
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Realm:        realm,
		DebugActive:  debugActive,
	}
}

func (auth *KeycloakMiddleware) AuthorizeMessage(msg *amqp091.Delivery) error {
	token, err := ExtractBearerTokenFromMessage(msg)
	if err != nil {
		log.Printf("Unable to extract token %s\n", err)
		return err
	}

	return verifyToken(token, auth)
}

func (auth *KeycloakMiddleware) AuthorizeHttpRequest(request http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		token, err := ExtractBearerTokenFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err.Error())
			return
		}

		err = verifyToken(token, auth)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			log.Print(err)
			return
		}

		request.ServeHTTP(w, r)
	}

	return http.HandlerFunc(f)
}

func (auth *KeycloakMiddleware) ExtractUserIdFromToken(token *string) (string, error) {
	return extractUserIdFromToken(*token, auth.KeyCloakConfig)
}

func extractUserIdFromToken(token string, keyCloakConfig *Configuration) (string, error) {
	goCloak := keyCloakConfig.GoCloak
	_, claims, err := goCloak.DecodeAccessToken(context.Background(), token, keyCloakConfig.Realm)
	if err != nil {
		return "", err
	}

	id := (*claims)["sub"]
	return fmt.Sprintf("%v", id), nil
}

func ExtractUserIdFromRequest(r *http.Request, keyCloakConfig *Configuration) (string, error) {
	token, err := ExtractBearerTokenFromRequest(r)
	if err != nil {
		return "", err
	}

	userId, err := extractUserIdFromToken(token, keyCloakConfig)
	if err != nil {
		return "", err
	}

	return userId, nil
}

func GetAuthorizationHeaderFromRequest(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return "", fmt.Errorf("authorization header missing")
	}
	return token, nil
}

func GetAuthorizationHeaderFromMessage(msg *amqp091.Delivery) (string, error) {
	token := msg.Headers["Authorization"]
	if token == "" {
		return "", fmt.Errorf("authorization header missing")
	}
	return token.(string), nil
}

func verifyToken(token string, auth *KeycloakMiddleware) error {

	goCloakConfig := auth.KeyCloakConfig
	goCloak := goCloakConfig.GoCloak
	goCloak.RestyClient().SetDebug(auth.KeyCloakConfig.DebugActive)

	log.Println(token)

	result, err := goCloak.RetrospectToken(context.Background(), token, goCloakConfig.ClientId, goCloakConfig.ClientSecret, goCloakConfig.Realm)
	if err != nil {
		return fmt.Errorf("invalid or malformed token: %s", err.Error())
	}

	if !*result.Active {
		return fmt.Errorf("invalid or expired token")
	}

	return nil
}

func ExtractBearerTokenFromRequest(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	return extractToken(token)
}

func ExtractBearerTokenFromMessage(msg *amqp091.Delivery) (string, error) {
	token := msg.Headers["Authorization"]
	if token == nil {
		return "", fmt.Errorf("authorization header missing")
	}

	return extractToken(token.(string))
}

func extractToken(token string) (string, error) {
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

func getOrFail(envVar string) string {
	val := os.Getenv(envVar)
	if val == "" {
		log.Fatalf("param {%s} must be provided", envVar)
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
