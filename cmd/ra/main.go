package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/mux"
	"github.com/zero-trust/zt-identity/pkg/ca"
	"github.com/zero-trust/zt-identity/pkg/models"
)

const (
	defaultPort   = "8443"
	defaultCADir  = "ca"
	spiffePrefix  = "spiffe://demo/ns/default/sa/"
)

type store struct {
	mu         sync.RWMutex
	identities map[string]*models.ServiceIdentity
	tokens     map[string]*models.BootstrapToken
	certs      map[string]*models.IssuedCert
	revoked    map[string]*models.RevocationEntry
}

type server struct {
	store *store
	ca    *ca.Config
}

func main() {
	port := os.Getenv("RA_PORT")
	if port == "" {
		port = defaultPort
	}
	cadir := os.Getenv("CA_DIR")
	if cadir == "" {
		cadir = defaultCADir
	}

	s := &server{
		store: &store{
			identities: make(map[string]*models.ServiceIdentity),
			tokens:     make(map[string]*models.BootstrapToken),
			certs:      make(map[string]*models.IssuedCert),
			revoked:    make(map[string]*models.RevocationEntry),
		},
		ca: &ca.Config{BaseDir: cadir},
	}

	r := mux.NewRouter()
	r.HandleFunc("/v1/register", s.handleRegister).Methods("POST")
	r.HandleFunc("/v1/issue", s.handleIssue).Methods("POST")
	r.HandleFunc("/v1/revoke", s.handleRevoke).Methods("POST")
	r.HandleFunc("/v1/status", s.handleStatus).Methods("GET")

	log.Printf("RA listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// TODO: auth admin
	serviceID := r.URL.Query().Get("service")
	if serviceID == "" {
		http.Error(w, "missing service", http.StatusBadRequest)
		return
	}
	token := "zt-bootstrap-" + randomHex(16)
	spiffeID := spiffePrefix + serviceID
	ident := &models.ServiceIdentity{
		ID:       serviceID,
		SpiffeID: spiffeID,
		Active:   true,
	}
	s.store.mu.Lock()
	s.store.identities[serviceID] = ident
	s.store.tokens[token] = &models.BootstrapToken{
		ServiceID: serviceID,
		Token:     token,
		Used:      false,
	}
	s.store.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"bootstrap_token":"` + token + `","spiffe_id":"` + spiffeID + `"}`))
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Bootstrap-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		http.Error(w, "missing bootstrap token", http.StatusUnauthorized)
		return
	}
	s.store.mu.Lock()
	bt, ok := s.store.tokens[token]
	if !ok || bt.Used {
		s.store.mu.Unlock()
		http.Error(w, "invalid or used token", http.StatusUnauthorized)
		return
	}
	serviceID := bt.ServiceID
	bt.Used = true
	spiffeID := spiffePrefix + serviceID
	s.store.mu.Unlock()

	certPEM, keyPEM, chainPEM, serial, err := s.ca.IssueLeaf(spiffeID, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// TODO: parse expires from cert
	ic := &models.IssuedCert{
		Serial:    serial,
		ServiceID: serviceID,
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  chainPEM,
	}
	s.store.mu.Lock()
	s.store.certs[serial] = ic
	s.store.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"cert_pem":"` + certPEM + `","key_pem":"` + keyPEM + `","chain_pem":"` + chainPEM + `","serial":"` + serial + `"}`))
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	// TODO: auth admin
	serial := r.URL.Query().Get("serial")
	service := r.URL.Query().Get("service")
	if serial == "" && service == "" {
		http.Error(w, "serial or service required", http.StatusBadRequest)
		return
	}
	s.store.mu.Lock()
	if service != "" {
		for ser, ic := range s.store.certs {
			if ic.ServiceID == service {
				s.store.revoked[ser] = &models.RevocationEntry{Serial: ser, Reason: "revoked"}
			}
		}
	} else {
		s.store.revoked[serial] = &models.RevocationEntry{Serial: serial, Reason: "revoked"}
	}
	s.store.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// TODO: auth admin
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"certs":[],"revoked":[]}`))
}

func randomHex(n int) string {
	b := make([]byte, n/2+1)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
