package mutations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCreateUser_Validation(t *testing.T) {
	cases := []struct {
		name    string
		in      CreateUserInput
		wantErr string
	}{
		{
			name: "valid",
			in:   CreateUserInput{DomainID: 1, Username: "alice", Password: "longenough"},
		},
		{
			name: "valid with quota",
			in:   CreateUserInput{DomainID: 7, Username: "bob", Password: "longenough", QuotaMB: 2048},
		},
		{
			name:    "missing domain",
			in:      CreateUserInput{Username: "alice", Password: "longenough"},
			wantErr: "domain is required",
		},
		{
			name:    "empty username",
			in:      CreateUserInput{DomainID: 1, Username: "", Password: "longenough"},
			wantErr: "username is required",
		},
		{
			name:    "whitespace only username",
			in:      CreateUserInput{DomainID: 1, Username: "   ", Password: "longenough"},
			wantErr: "username is required",
		},
		{
			name:    "username with @",
			in:      CreateUserInput{DomainID: 1, Username: "a@b", Password: "longenough"},
			wantErr: "may not contain",
		},
		{
			name:    "username with slash",
			in:      CreateUserInput{DomainID: 1, Username: "a/b", Password: "longenough"},
			wantErr: "may not contain",
		},
		{
			name:    "username with inner space",
			in:      CreateUserInput{DomainID: 1, Username: "a b", Password: "longenough"},
			wantErr: "may not contain",
		},
		{
			name:    "short password",
			in:      CreateUserInput{DomainID: 1, Username: "alice", Password: "short"},
			wantErr: "at least 8",
		},
		{
			name:    "negative quota",
			in:      CreateUserInput{DomainID: 1, Username: "alice", Password: "longenough", QuotaMB: -1},
			wantErr: "negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			err := validateCreateUser(&in)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateCreateUser(%+v) = %v, want nil", tc.in, err)
				}
				return
			}

			if err == nil {
				t.Fatalf("validateCreateUser(%+v) = nil, want error containing %q", tc.in, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("error = %v, want it to wrap ErrInvalidInput", err)
			}
		})
	}
}

func TestCreateUser_ValidationNormalizesUsername(t *testing.T) {
	in := CreateUserInput{DomainID: 1, Username: "  Alice.Cooper  ", Password: "longenough"}

	if err := validateCreateUser(&in); err != nil {
		t.Fatalf("validateCreateUser returned error for valid input: %v", err)
	}
	if in.Username != "alice.cooper" {
		t.Errorf("Username = %q, want %q", in.Username, "alice.cooper")
	}
}

func TestResetUserPassword_RejectsShortPassword(t *testing.T) {
	// The length guard runs before any DB access, so a zero-value Service is
	// enough to exercise it.
	s := &Service{}

	_, err := s.ResetUserPassword(context.Background(), Actor{Name: "admin:test"},
		ResetPasswordInput{UserID: 1, Password: "short"})

	if err == nil {
		t.Fatal("ResetUserPassword with a short password returned nil error")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want it to wrap ErrInvalidInput", err)
	}
}
