package didcomauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	challengeSize  = 1024             // number of random bytes fetched from crypto source
	jwtTokenExpiry = 30 * time.Second // seconds after which a JWT token becomes invalid
)

type Challenge struct {
	Challenge string `json:"challenge"`
	Timestamp int64  `json:"timestamp"`
	DID       string `json:"did,omitempty"`
}

// encoding.Binary{Marshaler,Unmarshaler} interface implementation
func (c Challenge) MarshalBinary() (data []byte, err error) {
	aaa, err := json.Marshal(c)
	return aaa, err
}

// SignaturePayload returns the bytes on which the user should have placed its signature.
func (c Challenge) SignaturePayload() []byte {
	ts := strconv.FormatInt(c.Timestamp, 10)
	return []byte(c.Challenge + ts + c.DID)
}

type AuthResponse struct {
	Challenge
	Response string `json:"response"`
}

// Validate checks that AuthResponse is valid and does not contains bogus data.
func (ar AuthResponse) Validate() error {
	switch {
	case ar.Challenge.Challenge == "":
		return errors.New("challenge field empty")
	case ar.Response == "":
		return errors.New("response field empty")
	case ar.DID == "":
		return errors.New("DID field empty")
	case ar.Timestamp <= 0:
		return errors.New("timestamp invalid")
	default:
		return nil
	}
}

// ResponseBytes returns the bytes representation of the base64-encoded Response field.
func (ar AuthResponse) ResponseBytes() ([]byte, error) {
	// decode base64 response to bytes
	rb, err := base64.StdEncoding.DecodeString(ar.Response)
	if err != nil {
		return nil, err
	}

	return rb, nil
}

// DidComAuthClaims represents the JWT claim we release after a successful DID authentication
type DidComAuthClaims struct {
	*jwt.StandardClaims
	Resource string `json:"resource"`
	DID      string `json:"did"`
}

// ReleaseJWTResponse represents a JSON struct which we return to a caller if the DID authentication is successful.
type ReleaseJWTResponse struct {
	Token string `json:"token"`
}
