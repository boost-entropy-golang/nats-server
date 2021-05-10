package test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"golang.org/x/crypto/ocsp"
)

func TestOCSP(t *testing.T) {
	const (
		caCert     = "configs/certs/ocsp/ca-cert.pem"
		caKey      = "configs/certs/ocsp/ca-key.pem"
		serverCert = "configs/certs/ocsp/server-cert.pem"
		serverKey  = "configs/certs/ocsp/server-key.pem"
	)
	ocspr := newOCSPResponder(t, caCert, caKey)
	defer ocspr.Close()
	setOCSPStatus(t, ocspr.URL, serverCert, ocsp.Good)

	opts := DefaultTestOptions
	opts.Port = -1
	opts.TLSCert = serverCert
	opts.TLSKey = serverKey
	opts.TLSCaCert = caCert
	opts.TLSTimeout = 5

	var err error
	opts.TLSConfig, opts.OCSPConfig, err = server.GenOCSPConfig(&server.TLSConfigOpts{
		CertFile:           opts.TLSCert,
		KeyFile:            opts.TLSKey,
		CaFile:             opts.TLSCaCert,
		OCSPMode:           server.OCSPModeAuto,
		OCSPStatusDir:      createDir(t, "ocsp-status"),
		OCSPServerOverride: []string{ocspr.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts.OCSPConfig.MinWait = 1 * time.Second

	doLog = true
	s := RunServer(&opts)
	defer s.Shutdown()
	defer removeDir(t, opts.OCSPConfig.StatusDir)

	go func() {
		time.Sleep(5 * time.Second)
		setOCSPStatus(t, ocspr.URL, serverCert, ocsp.Revoked)
	}()

	time.Sleep(12 * time.Second)
}

func newOCSPResponder(t *testing.T, issuerCertPEM, issuerKeyPEM string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	status := make(map[string]int)

	issuerCert := parseCertPEM(t, issuerCertPEM)
	issuerKey := parseKeyPEM(t, issuerKeyPEM)

	mux := http.NewServeMux()
	// The "/statuses/" endpoint is for directly setting a key-value pair in
	// the CA's status database.
	mux.HandleFunc("/statuses/", func(rw http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		key := r.URL.Path[len("/statuses/"):]
		switch r.Method {
		case "GET":
			mu.Lock()
			n, ok := status[key]
			if !ok {
				n = ocsp.Unknown
			}
			mu.Unlock()

			fmt.Fprintf(rw, "%s %d", key, n)
		case "POST":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}

			n, err := strconv.Atoi(string(data))
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadRequest)
				return
			}

			mu.Lock()
			status[key] = n
			mu.Unlock()

			fmt.Fprintf(rw, "%s %d", key, n)
		default:
			http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	})
	// The "/" endpoint is for normal OCSP requests. This actually parses an
	// OCSP status request and signs a response with a CA. Lightly based off:
	// https://www.ietf.org/rfc/rfc2560.txt
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		reqData, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		ocspReq, err := ocsp.ParseRequest(reqData)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		n, ok := status[ocspReq.SerialNumber.String()]
		if !ok {
			n = ocsp.Unknown
		}
		mu.Unlock()

		tmpl := ocsp.Response{
			Status:       n,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(4 * time.Second),
		}
		respData, err := ocsp.CreateResponse(issuerCert, issuerCert, tmpl, issuerKey)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/ocsp-response")
		rw.Header().Set("Content-Length", fmt.Sprint(len(respData)))

		fmt.Fprint(rw, string(respData))
	})

	return httptest.NewServer(mux)
}

func setOCSPStatus(t *testing.T, ocspURL, certPEM string, status int) {
	t.Helper()

	cert := parseCertPEM(t, certPEM)

	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Post(
		fmt.Sprintf("%s/statuses/%s", ocspURL, cert.SerialNumber),
		"",
		strings.NewReader(fmt.Sprint(status)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read OCSP HTTP response body: %s", err)
	}

	if got, want := resp.Status, "200 OK"; got != want {
		t.Error(strings.TrimSpace(string(data)))
		t.Fatalf("unexpected OCSP HTTP set status, got %q, want %q", got, want)
	}
}

func parseCertPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block := parsePEM(t, certPEM)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert %s: %s", certPEM, err)
	}
	return cert
}

func parseKeyPEM(t *testing.T, keyPEM string) *rsa.PrivateKey {
	t.Helper()
	block := parsePEM(t, keyPEM)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse ikey %s: %s", keyPEM, err)
	}
	return key
}

func parsePEM(t *testing.T, pemPath string) *pem.Block {
	t.Helper()
	data, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("failed to decode PEM %s", pemPath)
	}
	return block
}
