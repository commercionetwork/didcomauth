# `didcomauth`: commercio.network DID-based HTTP authentication

This package implements [commercio.network](https://github.com/commercionetwork/commercionetwork)\-based
 authentication, leveraging [`gorilla/mux`](http://github.com/gorilla/mux) for route management.
 
Authentication happens if the user can prove the ownership of its DID by signing a challenge with its signing key.

A resource-based JWT token is released to the user that can prove the ownership of its DID, assuming he was authorized
by the resource owner to access it.

DID resolution happens on the [commercio.network](https://github.com/commercionetwork/commercionetwork) blockchain, 
assuming that the user created a DID on it.

## Endpoints

`didcomauth` adds the following endpoints to your mux:

 - a challenge URL, by default on `/auth/challenge`
 - a subdirectory under which every HTTP handler requires DID authentication, by default `/protected`
 
The protected path can be customized, refer to the `godoc` for more information.

Each HTTP call requires two headers to be specified:

 - `X-DID`, the DID which should be authenticated
 - `X-Resource`, the resource to be accessed

Each protected handler can decide whether allowing or not access to a specific resource based on the `X-Resource` header,
`didcomauth`'s concerns revolve around authentication only.

 
## Example server

```go
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

```