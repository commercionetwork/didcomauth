package didcomauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_writeError(t *testing.T) {
	h := func(e error, status int) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			writeError(rw, status, e)
		})
	}

	tests := []struct {
		name   string
		e      error
		status int
	}{
		{
			"error gets serialized well",
			errors.New("error!"),
			http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/writeErrorTest", nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()

			h(tt.e, tt.status).ServeHTTP(rr, req)

			require.Equal(t, tt.status, rr.Code)
			require.Contains(t, rr.Body.String(), tt.e.Error())
		})
	}
}
