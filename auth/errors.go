package auth

import "errors"

var (
	errInvalidCredential = errors.New("auth: invalid credential")
	errCredentialClosed  = errors.New("auth: credential is closed")
)
