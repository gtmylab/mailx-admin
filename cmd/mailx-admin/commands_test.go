package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestCommandMentionsResolve is the regression guard for v1.6.39.
//
// That release fixed the rendered rate() rules and told every operator with a
// rate-limited domain to repair the host with `mailx-admin sync`. There is no
// such command at the top level -- `sync` exists only as `mailx-admin roundcube
// sync` -- so the one instruction that would have fixed the host exited with
// "unknown command: sync" and the host kept enforcing nothing. The build stayed
// green because a hint is just a string.
//
// So: walk the cobra tree, aliases included, and check every "mailx-admin
// <words>" phrase this repository prints at an operator. Prose after a real
// command is allowed -- the phrase is resolved against its longest prefix that
// is a command, so "run `mailx-admin reconcile` to render them" is fine.
func TestCommandMentionsResolve(t *testing.T) {
	known := commandPaths(newRootCmd())

	// The directories whose strings reach an operator. Config renderers are
	// deliberately left out: they contain markers such as
	// "# BEGIN mailx-admin managed block", which name no command.
	dirs := []string{
		"../../cmd/mailx-admin",
		"../../internal/doctor",
		"../../internal/server",
		"../../internal/mutations",
	}

	mention := regexp.MustCompile(`\bmailx-admin [a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)?`)

	// The guard has to be able to fail, and it has to accept the alias the hints
	// now use; otherwise it would only ever confirm what is already there.
	if _, ok := resolveMention(known, "mailx-admin syncronise"); ok {
		t.Error("the guard treats an unknown command as valid, so it cannot catch the v1.6.39 bug")
	}
	if got, ok := resolveMention(known, "mailx-admin sync"); !ok || got != "mailx-admin sync" {
		t.Errorf("`mailx-admin sync` does not resolve to a command (%q, %v), so the hints that name it are still broken", got, ok)
	}

	checked := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}

			path := filepath.Join(dir, name)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			for _, phrase := range mention.FindAllString(string(src), -1) {
				checked++
				if _, ok := resolveMention(known, phrase); !ok {
					t.Errorf("%s tells an operator to run %q, which is not a command; `mailx-admin --help` lists the ones that are",
						filepath.ToSlash(path), phrase)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no command mentions were found; the scan is not looking where the hints are")
	}
}

// TestSyncIsReconcile pins the alias the hints rely on: `sync` has to resolve,
// and to the same command -- not to a copy that drifts away from it.
func TestSyncIsReconcile(t *testing.T) {
	root := newRootCmd()

	reconcile, args, err := root.Find([]string{"reconcile"})
	if err != nil || len(args) != 0 {
		t.Fatalf("`mailx-admin reconcile` does not resolve: %v %v", err, args)
	}

	alias, args, err := root.Find([]string{"sync"})
	if err != nil || len(args) != 0 {
		t.Fatalf("`mailx-admin sync` does not resolve: %v %v", err, args)
	}
	if alias != reconcile {
		t.Fatalf("`mailx-admin sync` resolves to %q, want the same command as reconcile", alias.Name())
	}
	if alias.Name() != "reconcile" {
		t.Errorf("name = %q, want reconcile", alias.Name())
	}
	if !alias.HasAlias("sync") {
		t.Error("reconcile does not declare the sync alias, so the hints that name it would fail on the host")
	}
}

// commandPaths lists every way the tree can be spelled, aliases included.
func commandPaths(root *cobra.Command) map[string]bool {
	known := make(map[string]bool)

	var walk func(cmd *cobra.Command, parent string)
	walk = func(cmd *cobra.Command, parent string) {
		path := strings.TrimSpace(parent + " " + cmd.Name())
		known[path] = true
		for _, alias := range cmd.Aliases {
			known[strings.TrimSpace(parent+" "+alias)] = true
		}
		for _, child := range cmd.Commands() {
			walk(child, path)
		}
	}
	walk(root, "")

	return known
}

// resolveMention matches a "mailx-admin ..." phrase against the tree, longest
// prefix first, and returns the command it names.
func resolveMention(known map[string]bool, phrase string) (string, bool) {
	words := strings.Fields(phrase)
	for n := len(words); n >= 2; n-- {
		if command := strings.Join(words[:n], " "); known[command] {
			return command, true
		}
	}
	return "", false
}
