package keycloak

type ErrNoKeycloakUrls struct {
	message string
}

func newErrNoKeycloakUrls(message string) *ErrNoKeycloakUrls {
	return &ErrNoKeycloakUrls{
		message: message,
	}
}

func (e *ErrNoKeycloakUrls) Error() string {
	return e.message
}

type ErrOpenIDConfiguration struct {
	message string
	originalMessage string
}


func newErrOpenIDConfiguration(message string, originalMessage string) *ErrOpenIDConfiguration {
	return &ErrOpenIDConfiguration{
		message: message,
		originalMessage: originalMessage,
	}
}

func (e *ErrOpenIDConfiguration) Error() string {
	return e.message + ": '" + e.originalMessage + "'"
}

type ErrNoBearerToken struct {
	message string
}

func newErrNoBearerToken(message string) *ErrNoBearerToken {
	return &ErrNoBearerToken{
		message: message,
	}
}

func (e *ErrNoBearerToken) Error() string {
	return e.message
}

type ErrUnauthorized struct {
	message string
}

func newErrUnauthorized(message string) *ErrUnauthorized {
	return &ErrUnauthorized{
		message: message,
	}
}

func (e *ErrUnauthorized) Error() string {
	return e.message
}

type ErrForbidden struct {
	message string
}

func newErrForbidden(message string) *ErrForbidden {
	return &ErrForbidden{
		message: message,
	}
}

func (e *ErrForbidden) Error() string {
	return e.message
}