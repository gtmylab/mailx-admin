package ssl

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CertInfo struct {
	CertName   string
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	DaysLeft   int
	SANs       []string
	Serial     string
	SigAlg     string
	KeyBits    int
	ChainCount int
	Status     string // ok, warning, critical, expired, missing
}

// Inspect reads the certbot-managed cert for `certName`.
func Inspect(certName, letsencryptDir string) (*CertInfo, error) {
	fullchain := filepath.Join(letsencryptDir, "live", certName, "fullchain.pem")
	data, err := os.ReadFile(fullchain)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fullchain, err)
	}

	var leaf *x509.Certificate
	var chain int

	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain++
		if leaf == nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse leaf: %w", err)
			}
			leaf = cert
		}
	}

	if leaf == nil {
		return nil, fmt.Errorf("no certificate found in %s", fullchain)
	}

	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	status := "ok"
	switch {
	case daysLeft < 0:
		status = "expired"
	case daysLeft <= 7:
		status = "critical"
	case daysLeft <= 21:
		status = "warning"
	}

	keyBits := 0
	switch pub := leaf.PublicKey.(type) {
	case interface{ Size() int }:
		keyBits = pub.Size() * 8
	}

	return &CertInfo{
		CertName:   certName,
		Subject:    leaf.Subject.String(),
		Issuer:     leaf.Issuer.String(),
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		DaysLeft:   daysLeft,
		SANs:       leaf.DNSNames,
		Serial:     leaf.SerialNumber.String(),
		SigAlg:     leaf.SignatureAlgorithm.String(),
		KeyBits:    keyBits,
		ChainCount: chain,
		Status:     status,
	}, nil
}

// RenewRequest triggers certbot renew.
type RenewRequest struct {
	DryRun   bool
	Force    bool
	CertName string // empty = renew all
}

type RenewResult struct {
	Success  bool
	Duration time.Duration
	Output   string
	Error    string
}

func Renew(ctx context.Context, req RenewRequest) *RenewResult {
	args := []string{"renew", "--quiet", "--post-hook", "systemctl reload postfix dovecot apache2"}
	if req.DryRun {
		args = append(args, "--dry-run")
	}
	if req.Force {
		args = append(args, "--force-renewal")
	}
	if req.CertName != "" {
		args = append(args, "--cert-name", req.CertName)
	}

	cmd := exec.CommandContext(ctx, "certbot", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	start := time.Now()
	err := cmd.Run()
	res := &RenewResult{
		Duration: time.Since(start),
		Output:   buf.String(),
	}

	if err != nil {
		res.Success = false
		res.Error = err.Error()
		return res
	}
	res.Success = true
	return res
}

// InspectRemote connects to a host:port and returns the leaf cert's NotAfter.
// Used for external verification (e.g., is the cert on 993 correct?).
func InspectRemote(ctx context.Context, host string, port int) (*CertInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// No TLS handshake here — just an early-out helper. Real inspection uses
	// crypto/tls. Leaving this stub for Phase 5 (external cert checks).
	return nil, fmt.Errorf("not implemented")
}

// Notify template rendering helpers

type NotifyContext struct {
	Hostname string
	Domain   string
	Cert     *CertInfo
	Reason   string
}

func RenderFailureEmail(nc NotifyContext) (subject, body string) {
	subject = fmt.Sprintf("[%s] SSL renewal FAILED for %s", nc.Hostname, nc.Domain)
	var b strings.Builder
	fmt.Fprintf(&b, "===========================================\n")
	fmt.Fprintf(&b, "SSL RENEWAL FAILURE — ACTION REQUIRED\n")
	fmt.Fprintf(&b, "===========================================\n\n")
	fmt.Fprintf(&b, "Server    : %s\n", nc.Hostname)
	fmt.Fprintf(&b, "Domain    : %s\n", nc.Domain)
	fmt.Fprintf(&b, "Time      : %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Reason    : %s\n\n", nc.Reason)

	if nc.Cert != nil {
		fmt.Fprintf(&b, "Certificate status:\n")
		fmt.Fprintf(&b, "  Subject : %s\n", nc.Cert.Subject)
		fmt.Fprintf(&b, "  Expires : %s\n", nc.Cert.NotAfter.Format(time.RFC3339))
		fmt.Fprintf(&b, "  Days    : %d\n\n", nc.Cert.DaysLeft)
	}

	fmt.Fprintf(&b, "WHAT TO DO:\n")
	fmt.Fprintf(&b, "1. SSH into the server\n")
	fmt.Fprintf(&b, "2. Run: certbot renew --dry-run\n")
	fmt.Fprintf(&b, "3. Check logs: tail -n 50 /var/log/letsencrypt/letsencrypt.log\n\n")
	fmt.Fprintf(&b, "Common causes:\n")
	fmt.Fprintf(&b, "  - Port 80 blocked (HTTP-01 challenge fails)\n")
	fmt.Fprintf(&b, "  - DNS changed / domain no longer points here\n")
	fmt.Fprintf(&b, "  - Rate limit hit\n")
	fmt.Fprintf(&b, "  - Webroot path missing\n\n")
	fmt.Fprintf(&b, "MANUAL RENEWAL:\n")
	fmt.Fprintf(&b, "  certbot renew --force-renewal\n")
	fmt.Fprintf(&b, "  systemctl reload postfix dovecot apache2\n\n")
	fmt.Fprintf(&b, "Check current cert status from the MailX Admin panel:\n")
	fmt.Fprintf(&b, "  SSL → select domain → View details\n")
	fmt.Fprintf(&b, "===========================================\n")
	return subject, b.String()
}

func RenderExpiryWarningEmail(nc NotifyContext) (subject, body string) {
	subject = fmt.Sprintf("[%s] SSL cert for %s expires in %d days",
		nc.Hostname, nc.Domain, nc.Cert.DaysLeft)
	var b strings.Builder
	fmt.Fprintf(&b, "===========================================\n")
	fmt.Fprintf(&b, "SSL CERTIFICATE EXPIRY WARNING\n")
	fmt.Fprintf(&b, "===========================================\n\n")
	fmt.Fprintf(&b, "Server     : %s\n", nc.Hostname)
	fmt.Fprintf(&b, "Domain     : %s\n", nc.Domain)
	fmt.Fprintf(&b, "Expires    : %s\n", nc.Cert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "Days left  : %d\n\n", nc.Cert.DaysLeft)
	fmt.Fprintf(&b, "Renewal either failed silently or has not yet run.\n\n")
	fmt.Fprintf(&b, "Check from the MailX Admin panel:\n")
	fmt.Fprintf(&b, "  SSL → %s → Renew now\n", nc.Domain)
	fmt.Fprintf(&b, "===========================================\n")
	return subject, b.String()
}
