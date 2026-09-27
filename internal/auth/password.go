package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters tuned for ~50ms on a modern server CPU.
// Adjust memory up if you have RAM to spare; the OWASP minimum is m=47104 (46 MiB), t=1, p=1.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword returns a PHC-formatted Argon2id string:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64salt>$<base64hash>
//
// This is the format Dovecot expects when prefixed with `{ARGON2ID}`.
func HashPassword(password string) (string, error) {
	return HashPasswordWithParams(password, DefaultArgon2Params)
}

func HashPasswordWithParams(password string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash,
	)
	return encoded, nil
}

// VerifyPassword checks a plaintext password against a PHC-formatted hash.
func VerifyPassword(password, encoded string) (bool, error) {
	p, salt, hash, err := decodeArgon2(encoded)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey(
		[]byte(password),
		salt,
		p.Iterations,
		p.Memory,
		p.Parallelism,
		p.KeyLength,
	)

	if subtle.ConstantTimeCompare(computed, hash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeArgon2(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return p, nil, nil, fmt.Errorf("unsupported argon2 version: %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, fmt.Errorf("decode hash: %w", err)
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

// DovecotHash returns the password hash in the format Dovecot's passwd-file
// expects: `{ARGON2ID}$argon2id$...`
func DovecotHash(password string) (string, error) {
	h, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	return "{ARGON2ID}" + h, nil
}
