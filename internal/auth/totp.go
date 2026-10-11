package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"image/png"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret returns a new base32-encoded TOTP secret.
func GenerateTOTPSecret() (string, error) {
	// 20 bytes = 160 bits, the RFC 4226 recommendation
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// TOTPProvisioningURI returns the otpauth:// URI that QR code generators use.
func TOTPProvisioningURI(accountName, issuer, secret string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      []byte(secret),
		SecretSize:  20,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", fmt.Errorf("generate totp key: %w", err)
	}
	return key.URL(), nil
}

// TOTPQRPNG renders the provisioning URI for accountName/issuer/secret as a
// square PNG QR code (size×size pixels), ready to embed as a data URI.
func TOTPQRPNG(accountName, issuer, secret string, size int) ([]byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Secret:      []byte(secret),
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}
	img, err := key.Image(size, size)
	if err != nil {
		return nil, fmt.Errorf("render totp qr: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("encode totp qr: %w", err)
	}
	return buf.Bytes(), nil
}

// VerifyTOTP checks a 6-digit code with a ±1 window (30s skew tolerance).
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	valid, err := totp.ValidateCustom(code, secret, timeNow(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
