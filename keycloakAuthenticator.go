package keycloak

import (
	"context"
	"github.com/mtrossbach/go-oidc"
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
	ClaimChecker OpenIDClaimCheckFunc
}

type OpenIDClaims struct {
	Audience string `json:"aud"`
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
	EmailVerified bool `json:"email_verified"`
	Gender string `json:"gender"`
	Birthdate string `json:"birthdate"`
	ZoneInfo string `json:"string"`
	Locale string `json:"locale"`
	PhoneNumber string `json:"phone_number"`
	PhoneNumberVerified string `json:"phone_number_verified"`
	RealmAccess RoleClaims `json:"realm_access"`
	Oid string `json:"oid"`
	Upn string `json:"upn"`
	AppId string `json:"appid"`
	Roles []string `json:"roles"`
}

type RoleClaims struct {
	Roles []string `json:"roles"`
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
type OpenIDClaimCheckFunc func(*OpenIDClaims) string

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
		ClaimChecker: func(claims *OpenIDClaims) string {
			return ""
		},
	}, nil
}

func DefaultErrorHandler(err error, c *gin.Context) {

	switch err.(type) {
	case *ErrForbidden:
		response := defaultErrorResponse{
			Time: time.Now(),
			Status: 403,
			Message: "Forbidden",
			Detail: &[]errorDetail{
				{
					Message: err.Error(),
				},
			},
		}

		c.AbortWithStatusJSON(403, response)
	default:
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


}

func (k *KeycloakAuthenticator)GetMiddleware() gin.HandlerFunc {
	return k.GetMiddlewareWithRequiredRole("")
}

func (k *KeycloakAuthenticator)GetMiddlewareWithRequiredRole(requiredRole string) gin.HandlerFunc {
	if len(requiredRole) > 0 {
		return k.GetMiddlewareWithAnyRequiredRoles([]string{requiredRole})
	} else {
		return k.GetMiddlewareWithAnyRequiredRoles([]string{})
	}
}

func (k *KeycloakAuthenticator)GetMiddlewareWithAnyRequiredRoles(requiredRoles []string) gin.HandlerFunc {
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
			var claims OpenIDClaims
			token.Claims(&claims)

			claimError := k.ClaimChecker(&claims)
			if len(claimError) > 0 {
				k.ErrorHandler(newErrForbidden(claimError), c)
				return
			}

			if len(requiredRoles) != 0 {
				found := false

				var roles []string
				for _, r := range claims.Roles {
					roles = append(roles, r)
				}
				for _, r := range claims.RealmAccess.Roles {
					roles = append(roles, r)
				}

				for _, r := range requiredRoles {
					if contains(roles, r) {
						found = true
						break
					}
				}

				if !found {
					k.ErrorHandler(newErrForbidden("you do not have the required role, access denied"), c)
					return
				}
			}

			c.Set(KeycloakToken, token)
			c.Set(KeycloakEmail, claims.Email)
			c.Set(KeycloakUsername, claims.PreferredUsername)
			c.Set(KeycloakSubjectId, token.Subject)
			c.Set(KeycloakClaims, claims)
			c.Next()
		} else {
			if error != nil {
				k.ErrorHandler(newErrUnauthorized(error.Error()), c)
			} else {
				k.ErrorHandler(newErrUnauthorized("Unauthorized"), c)
			}
			return
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
