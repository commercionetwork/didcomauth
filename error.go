package didcomauth

import (
	"encoding/json"
	"net/http"
)

func writeError(rw http.ResponseWriter, status int, err error) {

	d := struct {
		Error string `json:"error"`
	}{
		err.Error(),
	}

	b, _ := json.Marshal(d)
	http.Error(rw, string(b), status)
}
