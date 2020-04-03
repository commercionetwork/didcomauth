package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/commercionetwork/didcomauth"
	"github.com/gorilla/mux"
)

func main() {
	m := mux.NewRouter()

	err := didcomauth.Configure(didcomauth.Config{
		JWTSecret: "secret",
		CacheType: didcomauth.CacheTypeRedis,
		ProtectedPaths: []didcomauth.ProtectedMapping{
			{
				Methods: []string{http.MethodGet},
				Path:    "/upload/{id:(?:.+)}",
				Handler: uploadHandler,
			},
		},
	}, m)

	m.HandleFunc("/foo", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(writer, "Foo!")
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(":6969", m))
}

func uploadHandler(writer http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	id := vars["id"]

	fmt.Fprintf(writer, "your upload id is: %s", id)
}
