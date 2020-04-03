package didcomauth

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
)

// router is a convenience type used to hold data that should be used by router path handlers.
type router struct {
	config Config
	mr     *mux.Router
	cp     cache
}

// instance is a package instance of the router, instantiated by Configure.
// Subsequent calls to Configure will overwrite this instance.
var instance *router

// Configure configures DID:COM authentication endpoints on mr.
func Configure(c Config, r *mux.Router) error {
	if r == nil {
		return errors.New("router is nil")
	}

	if err := c.Validate(); err != nil {
		return err
	}
	instance = &router{
		c,
		r,
		c.CacheProvider,
	}

	setCosmosConfig()

	authSubrouter := r.PathPrefix(defaultAuthPath).Subrouter()
	authSubrouter.Use(neededHeadersMiddleware)
	authSubrouter.HandleFunc(defaultChallengePath, instance.challengeGETHandler).Methods(http.MethodGet)
	authSubrouter.HandleFunc(defaultChallengePath, instance.challengePOSTHandler).Methods(http.MethodPost)

	protectedPaths := r.PathPrefix(c.ProtectedBasePath).Subrouter()
	protectedPaths.Use(instance.checkAuthMiddleware)

	for _, mapping := range c.ProtectedPaths {
		protectedPaths.Handle(mapping.Path, mapping.Handler).Methods(mapping.Methods...)
	}

	return nil
}
