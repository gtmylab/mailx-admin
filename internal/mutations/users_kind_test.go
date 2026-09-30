package mutations

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// TestValidateCreateUserKind is the input contract for the two mailbox kinds.
// validateCreateUser is pure, so it runs on every build — including the ones
// where the SQLite driver is a stub.
func TestValidateCreateUserKind(t *testing.T) {
	base := func() CreateUserInput {
		return CreateUserInput{DomainID: 1, Username: "Al", Password: "correct horse battery", QuotaMB: 1024}
	}

	t.Run("unset kind becomes virtual", func(t *testing.T) {
		in := base()
		if err := validateCreateUser(&in); err != nil {
			t.Fatalf("validateCreateUser: %v", err)
		}
		if in.Kind != models.KindVirtual {
			t.Errorf("Kind = %q, want %q — every caller that predates kinds means a virtual mailbox",
				in.Kind, models.KindVirtual)
		}
		if in.Username != "al" {
			t.Errorf("Username = %q, want it normalized", in.Username)
		}
	})

	t.Run("system mailbox needs the account it belongs to", func(t *testing.T) {
		in := base()
		in.Kind = models.KindSystem
		if err := validateCreateUser(&in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("err = %v, want ErrInvalidInput: without uid/home the renderer writes the vmail defaults, "+
				"and Dovecot then cannot open a maildir owned by the account", err)
		}

		in.SysUID, in.SysGID, in.Home = 1000, 1000, "/home/al"
		if err := validateCreateUser(&in); err != nil {
			t.Errorf("validateCreateUser with a complete account: %v", err)
		}
	})

	t.Run("system home must be an absolute path", func(t *testing.T) {
		in := base()
		in.Kind, in.SysUID, in.SysGID, in.Home = models.KindSystem, 1000, 1000, "home/al"
		if err := validateCreateUser(&in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput for a relative home", err)
		}
	})

	t.Run("unknown kind is rejected", func(t *testing.T) {
		in := base()
		in.Kind = "postmaster"
		if err := validateCreateUser(&in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
}

// TestValidateCreateUserPassword: a pre-hashed password is accepted as-is — that
// is how a system mailbox keeps the Unix password it already has — but only in
// the passwd-file's own format.
func TestValidateCreateUserPassword(t *testing.T) {
	in := CreateUserInput{DomainID: 1, Username: "al", QuotaMB: 10}
	if err := validateCreateUser(&in); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v, want ErrInvalidInput for a missing password", err)
	}

	in.PasswordHash = "plaintext-not-a-hash"
	if err := validateCreateUser(&in); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v, want ErrInvalidInput for a hash with no {SCHEME} prefix", err)
	}

	in.PasswordHash = "{CRYPT}$6$rounds=5000$abcdefgh$xyz"
	if err := validateCreateUser(&in); err != nil {
		t.Errorf("validateCreateUser with a {CRYPT} hash: %v", err)
	}

	hash, err := (&Service{}).passwordHashFor(context.Background(), in)
	if err != nil || hash != in.PasswordHash {
		t.Errorf("passwordHashFor = %q, %v; want the supplied hash unchanged", hash, err)
	}
}

// TestHashPasswordUsesAVerifiableScheme: whichever scheme the local Dovecot
// supports, what lands in the passwd-file has to be checkable — that is the
// whole point of asking instead of assuming argon2id.
func TestHashPasswordUsesAVerifiableScheme(t *testing.T) {
	ctx := context.Background()
	password := "correct horse battery staple"

	hash, err := (&Service{}).hashPassword(ctx, password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	switch {
	case strings.HasPrefix(hash, "{ARGON2ID}"):
		ok, err := auth.VerifyPassword(password, strings.TrimPrefix(hash, "{ARGON2ID}"))
		if err != nil || !ok {
			t.Errorf("the {ARGON2ID} hash does not verify: ok=%v err=%v", ok, err)
		}
	case strings.HasPrefix(hash, "{SSHA512}"):
		ok, err := auth.VerifySSHA512(password, hash)
		if err != nil || !ok {
			t.Errorf("the {SSHA512} hash does not verify: ok=%v err=%v", ok, err)
		}
	default:
		t.Fatalf("hash %q carries no {SCHEME} prefix; Dovecot would have to guess", hash)
	}

	if ok, _ := auth.VerifySSHA512("not the password", hash); ok {
		t.Error("a wrong password verified against the new hash")
	}
}
