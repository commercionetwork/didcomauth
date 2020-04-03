package didcomauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func (r *router) challengePOSTHandler(rw http.ResponseWriter, req *http.Request) {
	did := req.Header.Get(DIDHeader)
	resource := req.Header.Get(ResourceHeader)

	// do we have a valid challenge for this did?
	challenge, err := r.cp.Get(did)
	if err != nil {
		writeError(rw, http.StatusBadRequest, errors.New("challenge not found"))
		return
	}

	// as soon as we return, delete the challenge
	defer r.cp.Delete(did)

	// does the did have a DDO?
	ddo, err := resolveDDO(r.config.CommercioLCD, did)
	if err != nil {
		writeError(rw, http.StatusBadRequest, err)
		return
	}

	// does the ddo has a public signing key?
	ddoKey, err := ddo.SigningPubKey()
	if err != nil {
		writeError(rw, http.StatusBadRequest, err)
		return
	}

	var ar AuthResponse
	// okay then, unmarshal!
	jdec := json.NewDecoder(req.Body)
	jdec.DisallowUnknownFields()
	err = jdec.Decode(&ar)

	if err != nil {
		writeError(rw, http.StatusBadRequest, fmt.Errorf("could not unmarshal payload, %w", err))
		return
	}

	if err = ar.Validate(); err != nil {
		writeError(rw, http.StatusBadRequest, err)
		return
	}

	// check if ar actually contains the challenge data
	if err = checkRespCacheValidity(ar, challenge); err != nil {
		writeError(rw, http.StatusForbidden, err)
		return
	}

	// decode base64 response to bytes
	rb, err := ar.ResponseBytes()
	if err != nil {
		writeError(rw, http.StatusBadRequest, errors.New("request format invalid"))
		return
	}

	phash := sha256.Sum256(ar.SignaturePayload())

	err = rsa.VerifyPKCS1v15(ddoKey, crypto.SHA256, phash[:], rb)
	if err != nil {
		writeError(rw, http.StatusForbidden, errors.New("response verification failed"))
		return
	}

	token, err := genJWT(resource, did, r.config.JWTSecret)
	if err != nil {
		log.Println(err)
		writeError(rw, http.StatusInternalServerError, errors.New("could not generate jwt token"))
		return
	}

	jenc := json.NewEncoder(rw)
	err = jenc.Encode(ReleaseJWTResponse{Token: token})
	if err != nil {
		writeError(rw, http.StatusInternalServerError, fmt.Errorf("could not marshal token, %w", err))
	}
}

func checkRespCacheValidity(ar AuthResponse, c Challenge) error {
	if ar.Timestamp != c.Timestamp ||
		ar.DID != c.DID {
		return errors.New("response payload invalid")
	}

	return nil
}

func genJWT(resource, did, signingKey string) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("HS512"))
	token.Claims = &DidComAuthClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(jwtTokenExpiry).Unix(),
		},
		Resource: resource,
		DID:      did,
	}

	return token.SignedString([]byte(signingKey))
}
