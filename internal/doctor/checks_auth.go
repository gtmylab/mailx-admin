package doctor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/dovecot"
	"github.com/gtmylab/mailx-admin/internal/roundcube"
)

// schemeCheck answers the first question a failed login raises: can this
// Dovecot verify the hashes the panel writes?
//
// There are two ways it cannot, and they look identical from the outside. The
// local Dovecot can have been built without the scheme the panel hashes with —
// libsodium is what adds ARGON2I/ARGON2ID — and a hash stored in a scheme the
// build does not know is refused however right the password is. Or the passdb's
// `scheme=` default can name a scheme the build does not know, which only
// affects a hash kept without a {SCHEME} prefix. The first is a mailbox created
// in the panel; the second is a line an operator added by hand. Neither is
// visible anywhere else in the panel, which is why it is checked here.
func schemeCheck(ctx context.Context, opts Options) Check {
	const name = "password scheme"
	if opts.Config == nil {
		return Check{}
	}

	out, err := dovecot.ProbeCached(ctx)
	if err != nil {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: "this Dovecot could not be asked which password schemes it supports: " + err.Error(),
			Hint: "the panel hashes with SSHA512, which every build can verify, until the probe answers; " +
				"run doctor on the mail server itself to check ARGON2ID is really available",
			Command: "doveadm pw -l",
		}
	}
	schemes := dovecot.ParseSchemes(out)

	// The same answer the reconciler and the mutation service use, from the
	// output we already have.
	resolution, err := dovecot.Resolve(ctx, opts.Config.Mail.PasswdScheme,
		func(context.Context) (string, error) { return out, nil })
	if err != nil {
		return Check{
			Name:    name,
			Status:  Fail,
			Detail:  err.Error(),
			Hint:    "a mailbox hashed with a scheme this Dovecot cannot verify never logs in",
			Command: "doveadm pw -l",
		}
	}

	passwdFile := filepath.Join(opts.Config.Mail.DovecotConfDir, "users")
	counts, err := dovecot.ScanHashSchemes(passwdFile)
	if err != nil && !os.IsNotExist(err) {
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	// What a hash with no {SCHEME} prefix is verified with. It is the passdb's
	// own `scheme=` when it has one and Dovecot's compiled-in default when it
	// does not — which is what the renderer writes when the panel could not ask
	// this host, so reading the file is the only way to know.
	unverifiable := unverifiableHashes(counts, schemes, passdbDefaultScheme(opts.Config.Mail.DovecotConfDir))
	mailboxes := 0
	for _, n := range counts {
		mailboxes += n
	}

	if len(unverifiable) > 0 {
		return Check{
			Name:   name,
			Status: Fail,
			Detail: "this Dovecot cannot verify " + strings.Join(unverifiable, ", ") +
				"; those mailboxes are refused at login",
			Hint: "set their password again in the panel (Users → the mailbox → password): " +
				"a fresh hash is written in " + resolution.Scheme + ", which this Dovecot can verify",
			Command: "doveadm pw -l",
		}
	}

	// A scheme this build lists is not the same as a login that works. {CRYPT}
	// is the one that proves it: the panel never writes it, it comes from
	// /etc/shadow, and what crypt() can check depends on what hashed the Unix
	// password. See unprovenHashes.
	if unproven := unprovenHashes(counts); len(unproven) > 0 {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: "this Dovecot can verify its own schemes, but " + strings.Join(unproven, ", ") +
				" came from /etc/shadow and no login has been proven for them",
			Hint: "whether crypt() can check a shadow hash depends on what hashed it — " +
				"yescrypt ($y$) is refused by a crypt() that does not know it, and the refusal is an " +
				"internal failure rather than a wrong password. Set their password again in the panel " +
				"(Users → the mailbox → password): that writes a " + resolution.Scheme + " hash and " +
				"proves the login",
			Command: "doveadm auth test <address>",
		}
	}

	if resolution.Fallback {
		// Two different reasons to be here: this build has no libsodium, or
		// the probe never got to answer. The hint has to match, or the
		// operator installs a library on a host where nothing asked for it.
		hint := "install libsodium (apt install libsodium23) and restart Dovecot to get the memory-hard scheme back"
		if !resolution.Known {
			hint = "run doctor on the mail server itself: the local Dovecot could not be asked, " +
				"so the panel is hashing with SSHA512 until it can be"
		}
		return Check{
			Name:   name,
			Status: Warn,
			Detail: resolution.Detail + fmt.Sprintf(" (%d mailbox hash(es) in %s, all verifiable)",
				mailboxes, passwdFile),
			Hint:    hint,
			Command: "doveadm pw -l",
		}
	}

	return Check{
		Name:   name,
		Status: OK,
		Detail: fmt.Sprintf("%s; %d mailbox hash(es) in %s, all verifiable",
			resolution.Detail, mailboxes, passwdFile),
	}
}

// passdbDefaultScheme is the scheme Dovecot verifies a hash with when the hash
// carries no {SCHEME} prefix: the passwd-file passdb's own `scheme=` argument
// when it has one, and otherwise Dovecot's compiled-in default for that passdb.
//
// Reading the drop-in rather than assuming the panel's resolved scheme matters,
// because the panel deliberately writes no `scheme=` when it could not ask the
// local Dovecot which schemes it supports (reconciler.RenderDovecotUsersConf).
// Such a file leaves Dovecot on its own default, so reporting hashes as
// unverifiable — or as fine — against a scheme the file never mentions would be a
// guess in the one check whose whole job is to answer this exactly.
func passdbDefaultScheme(dovecotConfDir string) string {
	data, err := os.ReadFile(filepath.Join(dovecotConfDir, "conf.d", "10-auth-mailx.conf"))
	if err != nil {
		return dovecot.DefaultPassdbScheme
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if v := strings.TrimPrefix(field, "scheme="); v != field && v != "" {
				return strings.ToUpper(v)
			}
		}
	}
	return dovecot.DefaultPassdbScheme
}

// unverifiableHashes lists what in a passwd-file this Dovecot cannot check.
//
// It is the whole point of the check, and it is pure so it can be tested
// without a Dovecot: counts comes from the passwd-file, schemes from
// `doveadm pw -l`, and defaultScheme is what an unprefixed hash would be
// verified with (the passdb's `scheme=`).
func unverifiableHashes(counts map[string]int, schemes dovecot.Schemes, defaultScheme string) []string {
	var unverifiable []string
	for scheme, n := range counts {
		if n == 0 {
			continue
		}
		if scheme == "(default)" {
			if !schemes.Has(defaultScheme) {
				unverifiable = append(unverifiable,
					fmt.Sprintf("%d hash(es) with no {SCHEME} (the passdb default, %s)", n, defaultScheme))
			}
			continue
		}
		if !schemes.Has(scheme) {
			unverifiable = append(unverifiable, fmt.Sprintf("%d {%s} hash(es)", n, scheme))
		}
	}
	sort.Strings(unverifiable)
	return unverifiable
}

// unprovenHashes lists hashes in a passwd-file whose *scheme* this Dovecot
// supports, but whose contents nobody has ever verified.
//
// {CRYPT} is the only one, and it deserves its own answer. Every line the panel
// writes carries the scheme it was hashed with — {ARGON2ID} or {SSHA512}, both of
// which the local Dovecot was asked about — while a {CRYPT} line is a hash the
// panel *imported* from /etc/shadow, and the CRYPT scheme hands those bytes
// straight to the host's crypt(3). Whether that can check a given hash depends on
// what produced it: a yescrypt ($y$) hash, which modern distributions write by
// default, is refused by a crypt() that does not know yescrypt — and the refusal
// is an internal failure rather than a wrong password, so the login dies with a
// temp_fail that names nothing.
//
// `doveadm pw -l` lists CRYPT on every build, so judging by scheme name alone
// reports these mailboxes as fine. That is the false reassurance this function
// removes: the honest answer is "the panel cannot vouch for this line", and the
// way to settle it is to set the password again — which writes a hash Dovecot can
// verify and, on the CLI path, proves the login (see
// mutations.Service.ensureLoginUsable).
func unprovenHashes(counts map[string]int) []string {
	var unproven []string
	for scheme, n := range counts {
		if n > 0 && scheme == dovecot.DefaultPassdbScheme {
			unproven = append(unproven, fmt.Sprintf("%d {%s} hash(es)", n, scheme))
		}
	}
	sort.Strings(unproven)
	return unproven
}

// passwdFileCheck reports whether the process that reads the passwd-file can
// actually open it.
//
// The panel owns /etc/dovecot/users and used to write it 0600 root:root, while
// Dovecot's auth process — the only thing that reads it — drops to the
// unprivileged `dovecot` user (default_internal_user) before it opens a passdb
// file. A file that process cannot open is not "a login with the wrong password":
// the passdb does not load, and every login is refused with nothing naming the
// file. The reconciler now writes it 0640 root:dovecot (see
// reconciler.dovecotPasswdOwner), so this checks the file that is *on disk* — an
// install that predates that change, and one where the chown could not be applied,
// both look exactly like a wrong password from the outside.
func passwdFileCheck(opts Options) Check {
	const name = "dovecot passwd file"
	if opts.Config == nil {
		return Check{}
	}

	path := filepath.Join(opts.Config.Mail.DovecotConfDir, "users")
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Check{
				Name:   name,
				Status: Info,
				Detail: "there is no " + path + " yet",
				Hint:   "the sync writes it as soon as there is a mailbox to render",
			}
		}
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	return passwdFileAccess(path, info.Mode().Perm())
}

// passwdFileAccess judges the mode of an existing passwd-file. It is separate
// from the stat above so the judgement can be tested everywhere: Go reports the
// mode of a Windows file as 0666 whatever it was created with, so a test that
// wrote a 0600 file and asserted on it would pass for the wrong reason there.
func passwdFileAccess(path string, mode os.FileMode) Check {
	const name = "dovecot passwd file"

	if mode&0o044 == 0 {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: fmt.Sprintf("%s is %04o, so only root can read it", path, mode),
			Hint: "Dovecot's auth process runs as the unprivileged `dovecot` user (default_internal_user) " +
				"and cannot open the passdb: `chgrp dovecot " + path + "` and `chmod 640 " + path + "` fixes it, " +
				"and so does the next sync",
			Command: "ps -eo user,args | grep '[d]ovecot/auth'",
		}
	}

	detail := fmt.Sprintf("%s is %04o", path, mode)
	if mode&0o004 != 0 {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: detail + ", readable by every user on the server",
			Hint: "it holds a password hash per mailbox: `chmod 640 " + path + "` keeps it readable by " +
				"root and the auth process without showing it to everybody else",
			Command: "chmod 640 " + path,
		}
	}
	return Check{Name: name, Status: OK, Detail: detail + ", readable by the auth process"}
}

// roundcubeCheck reports whether the panel's mailboxes have an account in
// Roundcube's own database.
//
// It is the check for "the mailbox exists, the password is right, and webmail
// still treats it as new". Roundcube creates the row itself at first login, so
// a missing row is not a refused login — it is a login without the mailbox' own
// From: address, language and preferences, and nothing in the panel shows that.
func roundcubeCheck(ctx context.Context, opts Options) Check {
	const name = "roundcube accounts"
	if opts.Config == nil {
		return Check{}
	}

	rc := opts.Config.Roundcube
	if !rc.Enabled {
		return Check{
			Name:   name,
			Status: Info,
			Detail: "the panel does not pre-seed Roundcube's database ([roundcube] is disabled)",
			Hint: "webmail still works — Roundcube creates the account at first login, " +
				"without the mailbox' own identity or preferences",
			Command: "mailx-admin roundcube sync",
		}
	}

	client := roundcube.New(rc.ToClientConfig())
	known, err := client.ListUsers(ctx)
	if err != nil {
		return Check{
			Name:    name,
			Status:  Warn,
			Detail:  fmt.Sprintf("Roundcube's database (%s) could not be read: %v", rc.Database, err),
			Hint:    "a mailbox created while this was failing has no webmail account yet",
			Command: "mailx-admin roundcube sync",
		}
	}

	if opts.Store == nil {
		return Check{
			Name:   name,
			Status: OK,
			Detail: fmt.Sprintf("%d account(s) in %s on %s", len(known), rc.Database, rc.MailHost),
		}
	}

	snap, err := opts.Store.Snapshot(ctx)
	if err != nil {
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	have := make(map[string]bool, len(known))
	for _, login := range known {
		have[strings.ToLower(login)] = true
	}

	// A row is keyed by the name it was created with. The panel pre-seeds the
	// address; the installer has always pre-seeded the bare UNIX user name, so
	// either one counts as "webmail knows this mailbox" — but a row matched only
	// by local part is called out separately, because it is not the row a
	// full-address login looks up: Roundcube creates that one itself, without
	// the identity and preferences the pre-seeded row was meant to carry.
	var missing, localOnly []string
	for _, u := range snap.Users {
		email := strings.ToLower(u.Email)
		if have[email] {
			continue
		}
		if local, _, ok := strings.Cut(email, "@"); ok && local != "" && have[local] {
			localOnly = append(localOnly, email)
			continue
		}
		missing = append(missing, email)
	}
	sort.Strings(missing)
	sort.Strings(localOnly)

	detail := fmt.Sprintf("%d account(s) in %s on %s; %d of %d mailbox(es) have no account",
		len(known), rc.Database, rc.MailHost, len(missing), len(snap.Users))
	if len(localOnly) > 0 {
		detail += fmt.Sprintf("; %d keyed by the bare user name rather than the address (%s)",
			len(localOnly), firstFew(localOnly, 5))
	}

	if len(missing) == 0 {
		if len(localOnly) == 0 {
			return Check{Name: name, Status: OK, Detail: detail}
		}
		return Check{
			Name:   name,
			Status: Warn,
			Detail: detail,
			Hint: "such a row is only matched by a login that omits the domain; " +
				"a login with the address gets a fresh account without those preferences",
			Command: "mailx-admin roundcube sync",
		}
	}
	return Check{
		Name:   name,
		Status: Warn,
		Detail: detail + ": " + firstFew(missing, 5),
		Hint: "webmail creates them at first login, without the mailbox' own identity, " +
			"language and preferences",
		Command: "mailx-admin roundcube sync",
	}
}

// firstFew renders a list for a one-line detail, so a server with 400 mailboxes
// does not produce a 400-address check.
func firstFew(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

// managesieveCheck reports whether the ManageSieve service is there at all.
//
// Filters are the one part of the panel whose failure mode is silence. The
// panel writes ~/sieve/managesieve.sieve itself, so a rule created here looks
// saved, and delivery reads the script — but Roundcube's Filters page talks to
// managesieved over port 4190, and that daemon only starts when the protocol is
// listed in `protocols`. An install whose `protocols` line was
// "imap pop3 lmtp" therefore shows a Filters page that cannot connect, with
// nothing anywhere saying why. Roundcube additionally needs the managesieve
// plugin enabled and pointing at the port, which is checked here too.
func managesieveCheck(opts Options) Check {
	const name = "managesieved (filters)"

	if opts.Config == nil {
		return Check{}
	}
	confDir := opts.Config.Mail.DovecotConfDir
	conf := filepath.Join(confDir, "dovecot.conf")

	src, err := os.ReadFile(conf)
	if err != nil {
		if os.IsNotExist(err) {
			return Check{
				Name:   name,
				Status: Info,
				Detail: "there is no " + conf + " on this host",
			}
		}
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	if !protocolsIncludeSieve(string(src)) {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: "`protocols` in " + conf + " does not list `sieve`, so managesieved never starts",
			Hint: "Roundcube's Filters page cannot connect and every filter saved from it is lost; " +
				"set `protocols = imap pop3 lmtp sieve` (re-running the installer does it) and restart Dovecot",
			Command: "systemctl restart dovecot",
		}
	}

	// The protocol being enabled is not the same as a listener existing: the
	// installer used to write a 10-master.conf with no managesieve-login block.
	if !managesieveListenerConfigured(confDir) {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: "`sieve` is enabled but no configuration file has a managesieve-login block, so nothing listens on 4190",
			Hint:   "add `service managesieve-login { inet_listener sieve { port = 4190 } }` and restart Dovecot (the installer does this too)",
		}
	}

	// `protocols` and the listener can both be right while nothing can start:
	// the daemon only exists in the dovecot-managesieved package, which the
	// installer used to install on the fresh path only.
	if !managesieveBinaryInstalled() {
		return Check{
			Name:    name,
			Status:  Warn,
			Detail:  "`sieve` is configured but the dovecot-managesieved package is not installed, so nothing listens on 4190",
			Hint:    "`protocols = ... sieve` has no daemon to start without the package",
			Command: "apt-get install -y dovecot-sieve dovecot-managesieved && systemctl restart dovecot",
		}
	}

	// Finally, ask the socket. Config files can say one thing and the running
	// daemon another, which is exactly the state that is hardest to diagnose.
	if !opts.SkipServices {
		greeting, err := managesieveGreeting("127.0.0.1:4190")
		if err != nil {
			return Check{
				Name:    name,
				Status:  Warn,
				Detail:  "configured, but nothing accepts a connection on 127.0.0.1:4190",
				Hint:    "the daemon may not be running, or it failed to start; `journalctl -u dovecot -n 30` says which",
				Command: "systemctl status dovecot",
			}
		}
		// A port that accepts and stays silent, or answers with something else,
		// is not ManageSieve. Roundcube reports that as the same "Unable to
		// connect" as a closed port, so the two are separated here.
		if !strings.Contains(greeting, "IMPLEMENTATION") {
			return Check{
				Name:    name,
				Status:  Warn,
				Detail:  "port 4190 answered " + strconv.Quote(greeting) + ", which is not a ManageSieve greeting",
				Hint:    "something else is bound to the port; `ss -ltnp | grep 4190` names the process",
				Command: "ss -ltnp | grep 4190",
			}
		}

		// Dovecot is answering, so anything still broken is Roundcube's half:
		// the plugin not enabled, pointed elsewhere, or the plugin directory
		// missing. That is where the operator's error message actually comes
		// from, and it has nothing to do with the mail server.
		if problem, found := roundcubeFiltersProblem(defaultRoundcubeRoot); found && problem != "" {
			return Check{
				Name:   name,
				Status: Warn,
				Detail: "127.0.0.1:4190 speaks ManageSieve, but " + problem,
				Hint:   "re-run the installer and choose \"Repair webmail filters (ManageSieve)\" (option 26); it rewrites host/port/TLS and enables the plugin",
			}
		}

		return Check{Name: name, Status: OK, Detail: "listening on 127.0.0.1:4190, Roundcube managesieve plugin enabled"}
	}

	return Check{Name: name, Status: OK, Detail: "`sieve` is enabled in " + conf}
}

// defaultRoundcubeRoot is where the installer puts Roundcube. The panel has no
// configuration key for it because the panel never writes into it; the path
// matches Mailx-Installer's, and it is only read when it exists.
const defaultRoundcubeRoot = "/var/www/html/roundcube"

// managesieveBinaryInstalled answers whether the managesieve daemons are on
// disk. Distributions ship `managesieve` and `managesieve-login` next to the
// other Dovecot binaries, so the glob covers both without pinning a name.
func managesieveBinaryInstalled() bool {
	matches, err := filepath.Glob("/usr/lib/dovecot/managesieve*")
	return err == nil && len(matches) > 0
}

// managesieveListenerConfigured looks for a managesieve-login service block in
// every file Dovecot reads.
//
// Only 10-master.conf used to be checked, which is wrong in both directions:
// the listener may equally live in its own conf.d/20-managesieve.conf (the
// conventional place for a drop-in) or anywhere else in conf.d. Reading the
// whole directory reports the port that actually exists.
func managesieveListenerConfigured(confDir string) bool {
	files, err := filepath.Glob(filepath.Join(confDir, "conf.d", "*.conf"))
	if err != nil {
		return false
	}
	files = append(files, filepath.Join(confDir, "dovecot.conf"))

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if strings.Contains(string(src), "managesieve-login") {
			return true
		}
	}
	return false
}

// managesieveGreeting returns the first line the server sends when the port is
// opened, and an error when nothing answers.
//
// The greeting is the only way to tell "no daemon" from "not a ManageSieve
// daemon": a plain TCP connect succeeds against any listener, and Roundcube
// shows the same message for both.
func managesieveGreeting(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if line == "" {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return "", err
	}

	// Close the session politely: an abandoned one is logged by managesieved
	// as an error, and that noise lands in the journal the operator is about to
	// be told to read.
	_, _ = fmt.Fprint(conn, "LOGOUT\r\n")

	return strings.TrimSpace(line), nil
}

// roundcubeFiltersProblem reports what stops Roundcube's Filters page from
// reaching the local managesieved.
//
// found is false when Roundcube is not installed at root, so the check stays
// silent on a server without webmail. problem is empty when the configuration
// looks right; only *set* values are judged, because the plugin already
// defaults to localhost:4190 without TLS and an unset key is not a defect.
func roundcubeFiltersProblem(root string) (problem string, found bool) {
	src, err := os.ReadFile(filepath.Join(root, "config", "config.inc.php"))
	if err != nil {
		return "", false
	}
	conf := string(src)
	settings := phpSettings(conf)

	if host, ok := settings["managesieve_host"]; ok {
		if h := strings.Trim(host, "'\" "); h != "127.0.0.1" && h != "localhost" {
			return "Roundcube points the managesieve plugin at " + strconv.Quote(h) + " instead of this host", true
		}
	}
	if port, ok := settings["managesieve_port"]; ok {
		if p := strings.Trim(port, "'\" "); p != "4190" {
			return "Roundcube's managesieve_port is " + strconv.Quote(p) + ", not 4190", true
		}
	}
	if tls, ok := settings["managesieve_usetls"]; ok {
		if t := strings.Trim(tls, "'\" "); t != "false" && t != "0" {
			return "Roundcube asks for STARTTLS on 4190, which the local managesieved does not offer", true
		}
	}
	if !strings.Contains(nonCommentLines(conf), "'managesieve'") {
		return "the managesieve plugin is not enabled in $config['plugins']", true
	}
	if _, err := os.Stat(filepath.Join(root, "plugins", "managesieve")); err != nil {
		return "Roundcube has no plugins/managesieve directory (the 'complete' package has it)", true
	}

	return "", true
}

// phpAssignment matches an active `$config['key'] = value;` line. `.` does not
// cross a newline in Go's regexp, so one match stays on one line.
var phpAssignment = regexp.MustCompile(`(?m)^[ \t]*\$config\['([A-Za-z0-9_]+)'\][ \t]*=[ \t]*(.+);[ \t]*$`)

// phpSettings parses the active assignments out of a Roundcube config file.
// The last assignment wins, as it does in PHP.
func phpSettings(src string) map[string]string {
	settings := make(map[string]string)
	for _, m := range phpAssignment.FindAllStringSubmatch(src, -1) {
		settings[m[1]] = strings.TrimSpace(m[2])
	}
	return settings
}

// nonCommentLines drops `//`, `#` and `/* */` comments, so a commented-out
// example cannot be mistaken for an active setting.
func nonCommentLines(src string) string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if inBlock {
			i := strings.Index(line, "*/")
			if i < 0 {
				continue
			}
			inBlock = false
			line = strings.TrimSpace(line[i+2:])
		}
		// Strip a block comment that opens and closes on this line, and
		// remember one that runs past the end of it.
		for {
			i := strings.Index(line, "/*")
			if i < 0 {
				break
			}
			j := strings.Index(line[i+2:], "*/")
			if j < 0 {
				inBlock = true
				line = strings.TrimSpace(line[:i])
				break
			}
			line = strings.TrimSpace(line[:i] + " " + line[i+2+j+2:])
		}
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// protocolsIncludeSieve answers whether Dovecot's `protocols` setting enables
// the sieve protocol, which is what starts managesieved.
//
// The last assignment wins (Dovecot reads the file top to bottom), comments are
// ignored, and the value is a whitespace-separated list — Dovecot accepts
// `protocols=imap pop3 lmtp sieve` as readily as one with spaces around the `=`.
func protocolsIncludeSieve(conf string) bool {
	enabled := false
	for _, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.HasPrefix(line, "protocols") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "protocols"))
		if !strings.HasPrefix(rest, "=") {
			// `protocols` on its own is not an assignment (and `protocol
			// imap {` in a different file never reaches here).
			continue
		}
		enabled = false
		for _, p := range strings.Fields(strings.TrimPrefix(rest, "=")) {
			if p == "sieve" {
				enabled = true
			}
		}
	}
	return enabled
}
