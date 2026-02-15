package main

import (
	"log"
	"net/http"
	"os"
)

const defaultPort = "8444"

func main() {
	port := os.Getenv("CRL_PORT")
	if port == "" {
		port = defaultPort
	}
	crlPath := os.Getenv("CRL_PATH")
	if crlPath == "" {
		crlPath = "ca/crl.pem"
	}

	http.HandleFunc("/crl", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(crlPath)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(data)
	})

	log.Printf("CRL publisher listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
