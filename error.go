package didcomauth

import (
	"encoding/json"
	"net/http"
)

type dcaError struct {
	Error string `json:"error"`
}

func writeError(rw http.ResponseWriter, status int, err error) {
	d := dcaError{Error: err.Error()}

	b, _ := json.Marshal(d)
	http.Error(rw, string(b), status)
}
