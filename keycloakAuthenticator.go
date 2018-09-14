package keycloak

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

const (
	KeycloakToken string = "KeycloakAuthenticatorToken"
	KeycloakEmail string = "KeycloakAuthenticatorEmail"
	KeycloakSubjectId string = "KeycloakAuthenticatorSubjectId"
	KeycloakUsername string = "KeycloakAuthenticatorUsername"
	KeycloakClaims string = "KeycloakAuthenticatorClaims"
)

type KeycloakAuthenticator struct {
	verifiers []*oidc.IDTokenVerifier
	ErrorHandler ErrorHandlerFunc
}

type OpenIDClaims struct {
	Name string `json:"name"`
	GivenName string `json:"given_name"`
	FamilyName string `json:"family_name"`
	MiddleName string `json:"middle_name"`
	Nickname string `json:"nickname"`
	PreferredUsername string `json:"preferred_username"`
	Profile string `json:"profile"`
	Picture string `json:"picture"`
	Website string `json:"website"`
	Email string `json:"email"`
	EmailVerified *bool `json:"email_verified"`
	Gender string `json:"gender"`
	Birthdate string `json:"birthdate"`
	ZoneInfo string `json:"string"`
	Locale string `json:"locale"`
	PhoneNumber string `json:"phone_number"`
	PhoneNumberVerified string `json:"phone_number_verified"`
}

type defaultErrorResponse struct {
	Time time.Time `json:"time"`
	Status int `json:"status"`
	Message string `json:"message"`
	Detail *[]errorDetail `json:"detail,omitempty"`
}

type errorDetail struct {
	Message string `json:"message,omitempty"`
}

type ErrorHandlerFunc func(error, *gin.Context)

func NewKeycloakAuthenticator(urls []string, errorHandler ErrorHandlerFunc) (*KeycloakAuthenticator, error) {
		ctx := context.Background()

	var verifiers []*oidc.IDTokenVerifier

	if len(urls) == 0 {
		return nil, newErrNoKeycloakUrls("no keycloak urls provided")
	}

	for _, keycloakUrl := range urls {
		provider, err := oidc.NewProvider(ctx, keycloakUrl)
		if err != nil {
			return nil, newErrOpenIDConfiguration("could not initialize OpenID configuration for " + keycloakUrl, err.Error())
		}

		verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		verifiers = append(verifiers, verifier)
	}

	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	return &KeycloakAuthenticator{
		verifiers: verifiers,
		ErrorHandler: errorHandler,
	}, nil
}

func DefaultErrorHandler(err error, c *gin.Context) {
	response := defaultErrorResponse{
		Time: time.Now(),
		Status: 401,
		Message: "Unauthorized",
		Detail: &[]errorDetail{
			{
				Message: err.Error(),
			},
		},
	}

	c.AbortWithStatusJSON(401, response)
}

func (k *KeycloakAuthenticator)GetMiddleware() gin.HandlerFunc {
	ctx := context.Background()

	return func(c *gin.Context) {
		rawAccessToken := c.GetHeader("Authorization")
		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			k.ErrorHandler(newErrNoBearerToken("no bearer token provided"), c)
			return
		}

		success := false
		var error error
		var token *oidc.IDToken

		for _, verifier := range k.verifiers {
			verifierToken, verifierError := verifier.Verify(ctx, parts[1])

			if verifierError != nil {
				if !strings.HasPrefix(verifierError.Error(), "oidc: id token issued by a different provider") {
					error = verifierError
				}
			} else {
				success = true
				token = verifierToken
			}
		}

		if success {
			c.Set(KeycloakToken, token)
			var claims OpenIDClaims
			token.Claims(&claims)
			c.Set(KeycloakEmail, claims.Email)
			c.Set(KeycloakUsername, claims.PreferredUsername)
			c.Set(KeycloakSubjectId, token.Subject)
			c.Set(KeycloakClaims, claims)
			c.Next()
		} else {
			k.ErrorHandler(newErrUnauthorized(error.Error()), c)
			return
		}
	}
}