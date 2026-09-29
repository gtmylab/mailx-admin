package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/db"
)

// installerTomlTemplate returns the admin.toml here-document that
// Mailx-Installer writes in Stage 13d (write_admin_toml) for the branch that
// emits driverLine, e.g. `driver = "sqlite"`. The installer lives in another
// repository and shares no code with the panel, so this is how the config the
// server will actually read is checked against the parser that reads it.
func installerTomlTemplate(t *testing.T, driverLine string) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "Mailx-Installer"))
	if err != nil {
		t.Fatalf("read the shipped installer: %v", err)
	}
	lines := strings.Split(string(raw), "\n")

	found := -1
	for i, line := range lines {
		if strings.Contains(line, driverLine) {
			found = i
			break
		}
	}
	if found < 0 {
		t.Fatalf("Mailx-Installer no longer writes %s", driverLine)
	}

	// Walk back to the "cat > ... <<EOF" that opens the here-document.
	start := -1
	for i := found; i >= 0; i-- {
		if strings.Contains(lines[i], "<<EOF") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no here-document opens before %s", driverLine)
	}

	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "EOF" {
			return strings.Join(lines[start+1:i], "\n")
		}
	}
	t.Fatalf("the here-document containing %s is never terminated by EOF", driverLine)
	return ""
}

// TestInstallerAdminTomlRoundTrips — admin.toml written by the installer must
// parse and must select the section the installer filled in. The driver name is
// what decides that: the old code compared against "sqlite"/"postgres" exactly,
// so a differently-spelled (but valid) name quietly produced an empty DSN.
func TestInstallerAdminTomlRoundTrips(t *testing.T) {
	cases := []struct {
		driverLine string
		want       db.Driver
	}{
		{`driver = "sqlite"`, db.DriverSQLite},
		{`driver = "postgres"`, db.DriverPostgres},
	}

	for _, tc := range cases {
		tmpl := installerTomlTemplate(t, tc.driverLine)

		path := filepath.Join(t.TempDir(), "admin.toml")
		if err := os.WriteFile(path, []byte(tmpl), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(installer template with %s) = %v\n--- template ---\n%s", tc.driverLine, err, tmpl)
		}

		got := cfg.DB.ToDriverConfig()
		if got.Driver != tc.want {
			t.Errorf("installer template with %s: driver = %q, want %q", tc.driverLine, got.Driver, tc.want)
		}

		switch tc.want {
		case db.DriverSQLite:
			if got.SQLitePath == "" {
				t.Error("installer template has no [database.sqlite] path")
			}
		case db.DriverPostgres:
			if got.PGHost == "" || got.PGPort == 0 || got.PGDatabase == "" {
				t.Errorf("installer template [database.postgres] host/port/dbname = %q/%d/%q, want all set",
					got.PGHost, got.PGPort, got.PGDatabase)
			}
		}
	}
}

// TestToDriverConfigNormalizesDriverName — the canonical name chooses which
// section supplies the DSN, so every accepted spelling must reach that section.
func TestToDriverConfigNormalizesDriverName(t *testing.T) {
	cases := []struct {
		in   string
		want db.Driver
	}{
		{"sqlite", db.DriverSQLite},
		{"sqlite3", db.DriverSQLite},
		{"SQLite3", db.DriverSQLite},
		{"postgres", db.DriverPostgres},
		{"postgresql", db.DriverPostgres},
		{"pgx", db.DriverPostgres},
	}

	for _, tc := range cases {
		c := DBConfig{
			Driver:   tc.in,
			SQLite:   SQLiteConfig{Path: "/var/lib/mailx/mailx.db"},
			Postgres: PostgresConfig{Host: "127.0.0.1", Port: 5432, User: "mailx_admin", DBName: "mailx_admin", SSLMode: "disable"},
		}

		got := c.ToDriverConfig()
		if got.Driver != tc.want {
			t.Errorf("ToDriverConfig(%q).Driver = %q, want %q", tc.in, got.Driver, tc.want)
		}

		switch tc.want {
		case db.DriverSQLite:
			if got.SQLitePath != "/var/lib/mailx/mailx.db" {
				t.Errorf("driver %q: SQLitePath = %q, want the [database.sqlite] path", tc.in, got.SQLitePath)
			}
		case db.DriverPostgres:
			if got.PGHost != "127.0.0.1" || got.PGDatabase != "mailx_admin" {
				t.Errorf("driver %q: host/dbname = %q/%q, want the [database.postgres] values",
					tc.in, got.PGHost, got.PGDatabase)
			}
		}
	}
}

// TestToDriverConfigKeepsUnknownDriver — an unsupported name is passed through
// so db.Open reports it, rather than being silently dropped here.
func TestToDriverConfigKeepsUnknownDriver(t *testing.T) {
	cfg := DBConfig{Driver: "mysql"}
	if got := cfg.ToDriverConfig(); got.Driver != "mysql" {
		t.Errorf("ToDriverConfig(mysql).Driver = %q, want it passed through", got.Driver)
	}
}
