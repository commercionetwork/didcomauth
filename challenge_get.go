package didcomauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (r *router) challengeGETHandler(rw http.ResponseWriter, req *http.Request) {
	did := req.Header.Get(DIDHeader)

	challengeStr, err := getRandomChallenge()
	if err != nil {
		writeError(rw, http.StatusInternalServerError, err)
		return
	}

	timestamp := time.Now().Unix()

	c := Challenge{
		Challenge: challengeStr,
		Timestamp: timestamp,
		DID:       did,
	}

	err = r.cp.Set(c)

	if err != nil {
		log.Println(err)
		writeError(rw, http.StatusInternalServerError, errors.New("could not process Challenge"))
		return
	}

	jenc := json.NewEncoder(rw)
	err = jenc.Encode(c)

	if err != nil {
		writeError(
			rw,
			http.StatusInternalServerError,
			fmt.Errorf("could not marshal Challenge, %w", err),
		)
	}

}

func getRandomChallenge() (string, error) {
	rb := make([]byte, challengeSize)
	n, err := rand.Read(rb)
	if err != nil {
		return "", fmt.Errorf("could not fetch Challenge, %w", err)
	}

	if n != challengeSize {
		return "", errors.New("could not get enough random data to assemble Challenge")
	}

	return base64.URLEncoding.EncodeToString(rb), nil
}
