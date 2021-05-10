package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

type OCSPMode uint8

const (
	// OCSPModeAuto staples a status, only if "status_request" is set in cert.
	OCSPModeAuto OCSPMode = iota
	OCSPModeAlways
	OCSPModeNever
)

type OCSPConfig struct {
	hc *http.Client

	mu   *sync.Mutex
	raw  []byte
	resp *ocsp.Response

	// MinWait is the minimum amount of time to wait between renewal attempts.
	MinWait time.Duration

	Leaf           *x509.Certificate
	Issuer         *x509.Certificate
	Mode           OCSPMode
	StatusDir      string
	ServerOverride []string
}

func (oc *OCSPConfig) getNextRun() time.Duration {
	oc.mu.Lock()
	lastValid := oc.resp
	oc.mu.Unlock()

	if lastValid == nil {
		// We don't have any valid validity interval data yet, use default.
		return oc.MinWait
	}

	now := time.Now()
	if lastValid.NextUpdate.IsZero() {
		// If response is missing NextUpdate, we check the day after.
		// Technically, if NextUpdate is missing, we can try whenever.
		// https://tools.ietf.org/html/rfc6960#section-4.2.2.1
		return 24 * time.Hour
	}

	// If we continuously fail, we cut the duration in half for each failure,
	// down to a minimum. In the happy path, the Responder pushes NextUpdate to
	// the future and the retry remain long.
	next := lastValid.NextUpdate.Sub(now) / 2
	if next < oc.MinWait {
		next = oc.MinWait
	}
	return next
}

func (oc *OCSPConfig) getStatus() ([]byte, *ocsp.Response, error) {
	raw, resp := oc.getCacheStatus()
	if len(raw) > 0 && resp != nil {
		return raw, resp, nil
	}

	var err error
	raw, resp, err = oc.getLocalStatus()
	if err == nil {
		return raw, resp, nil
	}

	return oc.getRemoteStatus()
}

func (oc *OCSPConfig) getCacheStatus() ([]byte, *ocsp.Response) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	return oc.raw, oc.resp
}

func (oc *OCSPConfig) getLocalStatus() ([]byte, *ocsp.Response, error) {
	key := fmt.Sprintf("%x", sha256.Sum256(oc.Leaf.Raw))
	oc.mu.Lock()
	raw, err := ioutil.ReadFile(filepath.Join(oc.StatusDir, key))
	oc.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}

	resp, err := ocsp.ParseResponse(raw, oc.Issuer)
	if err != nil {
		return nil, nil, err
	}
	if err := validOCSPResponse(resp); err != nil {
		return nil, nil, err
	}

	oc.mu.Lock()
	oc.raw = raw
	oc.resp = resp
	oc.mu.Unlock()

	return raw, resp, nil
}

func (oc *OCSPConfig) getRemoteStatus() ([]byte, *ocsp.Response, error) {
	getRequestBytes := func(u string, hc *http.Client) ([]byte, error) {
		resp, err := hc.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("non-ok http status: %d", resp.StatusCode)
		}

		return ioutil.ReadAll(resp.Body)
	}

	// Request documentation:
	// https://tools.ietf.org/html/rfc6960#appendix-A.1

	reqDER, err := ocsp.CreateRequest(oc.Leaf, oc.Issuer, nil)
	if err != nil {
		return nil, nil, err
	}

	reqEnc := base64.StdEncoding.EncodeToString(reqDER)

	responders := oc.Leaf.OCSPServer
	if len(oc.ServerOverride) > 0 {
		responders = oc.ServerOverride
	}

	var raw []byte
	for _, u := range responders {
		u = strings.TrimSuffix(u, "/")
		raw, err = getRequestBytes(fmt.Sprintf("%s/%s", u, reqEnc), oc.hc)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("exhusted ocsp servers: %w", err)
	}

	resp, err := ocsp.ParseResponse(raw, oc.Issuer)
	if err != nil {
		return nil, nil, err
	}
	if err := validOCSPResponse(resp); err != nil {
		return nil, nil, err
	}

	key := fmt.Sprintf("%x", sha256.Sum256(oc.Leaf.Raw))
	if err := writeOCSPStatus(oc.mu, oc.StatusDir, key, raw); err != nil {
		return nil, nil, fmt.Errorf("failed to write ocsp status: %w", err)
	}

	oc.mu.Lock()
	oc.raw = raw
	oc.resp = resp
	oc.mu.Unlock()

	return raw, resp, nil
}

func hasOCSPStatusRequest(cert *x509.Certificate) bool {
	tlsFeatures := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	const statusRequestExt = byte(5)
	const tlsFeaturesLen = 5

	// Example Value: [48 3 2 1 5]
	// Documentation:
	// https://tools.ietf.org/html/rfc6066

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(tlsFeatures) {
			continue
		}
		if len(ext.Value) != tlsFeaturesLen {
			continue
		}
		return ext.Value[tlsFeaturesLen-1] == statusRequestExt
	}

	return false
}

func parseCertPEM(name string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	// Ignoring left over byte slice.
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM cert %s", name)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM certificate type: %s", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

// getOCSPIssuer returns a CA cert from the given path. If the path is empty,
// then this checks a given cert chain. If both are empty, then it returns an
// error.
func getOCSPIssuer(issuerCert string, chain [][]byte) (*x509.Certificate, error) {
	var issuer *x509.Certificate
	var err error
	switch {
	case len(chain) == 1 && issuerCert == "":
		err = fmt.Errorf("require ocsp ca in chain or configuration")
	case issuerCert != "":
		issuer, err = parseCertPEM(issuerCert)
	case len(chain) > 1 && issuerCert == "":
		issuer, err = x509.ParseCertificate(chain[1])
	default:
		err = fmt.Errorf("invalid ocsp ca configuration")
	}
	if err != nil {
		return nil, err
	} else if !issuer.IsCA {
		return nil, fmt.Errorf("%s invalid ca basic constraints: is not ca", issuerCert)
	}

	return issuer, nil
}

// writeOCSPStatus writes an OCSP status to a temporary file then moves it to a
// new path, in an attempt to avoid corrupting existing data.
func writeOCSPStatus(mu *sync.Mutex, dir, file string, data []byte) error {
	mu.Lock()
	err := os.MkdirAll(dir, 0755)
	mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to create ocsp status dir: %w", err)
	}

	tmp, err := ioutil.TempFile(dir, "tmp-cert-status")
	if err != nil {
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	mu.Lock()
	err = os.Rename(tmp.Name(), filepath.Join(dir, file))
	mu.Unlock()
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}

	return nil
}

func ocspStatusString(n int) string {
	switch n {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	default:
		return "unknown"
	}
}

func validOCSPResponse(r *ocsp.Response) error {
	// Time validation not handled by ParseResponse.
	// https://tools.ietf.org/html/rfc6960#section-4.2.2.1
	if !r.NextUpdate.IsZero() && r.NextUpdate.Before(time.Now()) {
		t := r.NextUpdate.Format(time.RFC3339Nano)
		return fmt.Errorf("invalid ocsp NextUpdate, is past time: %s", t)
	}
	if r.ThisUpdate.After(time.Now()) {
		t := r.ThisUpdate.Format(time.RFC3339Nano)
		return fmt.Errorf("invalid ocsp ThisUpdate, is future time: %s", t)
	}

	return nil
}
