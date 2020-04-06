package didcomauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const authHeader = "Authorization"

var invalidTokenError = errors.New("invalid token")
var notAuthorized = errors.New("not authorized")

// checkAuth is a wrapper type used to easily test the JWT authentication
type checkAuth struct {
	next http.Handler
	r    *router
}

func (c checkAuth) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ah := req.Header.Get(authHeader)
	did := req.Header.Get(DIDHeader)
	resource := req.Header.Get(ResourceHeader)

	if ah == "" {
		writeError(w, http.StatusForbidden, notAuthorized)
		return
	}

	bearer := getBearer(ah)

	if bearer == "" {
		writeError(w, http.StatusForbidden, notAuthorized)
		return
	}

	token, tokenError := jwt.Parse(bearer, func(token *jwt.Token) (interface{}, error) {
		if tt, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || tt.Name != "HS512" {
			return nil, invalidTokenError
		}

		return []byte(c.r.config.JWTSecret), nil
	})

	if tokenError != nil {
		writeError(w, http.StatusForbidden, invalidTokenError)
		return
	}

	var claimsErr error
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["resource"] != resource || claims["did"] != did {
			claimsErr = invalidTokenError
		}
	} else {
		claimsErr = invalidTokenError
	}

	if claimsErr != nil {
		writeError(w, http.StatusForbidden, claimsErr)
		return
	}

	if resource != req.URL.Path {
		writeError(w, http.StatusForbidden, invalidTokenError)
		return
	}

	c.next.ServeHTTP(w, req)
}

func (r *router) checkAuthMiddleware(next http.Handler) http.Handler {
	return checkAuth{next, r}
}

func getBearer(b string) string {
	if !strings.HasPrefix(b, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(b, "Bearer ")
}
