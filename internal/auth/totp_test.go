package auth

import (
	"bytes"
	"net/url"
	"testing"
)

// TestTOTPProvisioningURIUsesProvidedSecret guards against the double-encoding
// bug: the otpauth URI must carry the same base32 secret that VerifyTOTP uses,
// not a re-encoded version (which would make every authenticator code invalid).
func TestTOTPProvisioningURIUsesProvidedSecret(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	uri, err := TOTPProvisioningURI("alice", "mailx-admin", secret)
	if err != nil {
		t.Fatalf("TOTPProvisioningURI: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	if got := u.Query().Get("secret"); got != secret {
		t.Fatalf("secret param = %q, want %q (the QR would enroll the wrong secret)", got, secret)
	}
}

// TestTOTPQRPNGProducesPNG ensures the QR path yields a real PNG, not an error.
func TestTOTPQRPNGProducesPNG(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	img, err := TOTPQRPNG("alice", "mailx-admin", secret, 200)
	if err != nil {
		t.Fatalf("TOTPQRPNG: %v", err)
	}
	pngMagic := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if len(img) < 8 || !bytes.Equal(img[:8], pngMagic) {
		t.Fatalf("TOTPQRPNG did not return a valid PNG (%d bytes)", len(img))
	}
}
