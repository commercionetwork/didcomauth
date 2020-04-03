package didcomauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cosmos/cosmos-sdk/types"
)

const (
	DIDHeader      = "X-DID"
	ResourceHeader = "X-Resource"
)

type neededHeaders struct {
	next http.Handler
}

func (n neededHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	did := r.Header.Get(DIDHeader)
	resource := r.Header.Get(ResourceHeader)

	if did == "" {
		writeError(w, http.StatusBadRequest, errors.New(
			"X-DID header not defined",
		))
		return
	}

	if resource == "" {
		writeError(w, http.StatusBadRequest, errors.New(
			"X-Resource header not defined",
		))
		return
	}

	if err := checkDID(did); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	n.next.ServeHTTP(w, r)
}

// neededHeadersMiddleware checks that X-DID and X-Resource headers are present and valid.
func neededHeadersMiddleware(next http.Handler) http.Handler {
	return neededHeaders{next}
}

// checkDID checks that did is a Commercio.network one.
func checkDID(did string) error {
	if _, err := types.AccAddressFromBech32(did); err != nil {
		return fmt.Errorf("invalid DID, %w", err)
	}

	return nil
}
