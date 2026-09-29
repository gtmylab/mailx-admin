package doctor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

// configCheck renders the configuration but in dry-run mode: it shows whether
// the files on disk match what the database says, without writing anything.
func configCheck(ctx context.Context, opts Options) Check {
	if opts.Rec == nil || opts.Store == nil {
		return Check{}
	}

	cfg := opts.Rec.Config()
	cfg.DryRun = true
	cfg.SkipServiceReload = true

	snap, err := opts.Store.Snapshot(ctx)
	if err != nil {
		return Check{Name: "configuration files", Status: Fail, Detail: err.Error()}
	}

	res, err := reconciler.New(cfg, nil).Reconcile(ctx, snap)
	if err != nil {
		return Check{
			Name:    "configuration files",
			Status:  Fail,
			Detail:  err.Error(),
			Hint:    "a sync cannot complete, so panel changes never reach Postfix and Dovecot",
			Command: "mailx-admin reconcile --dry-run --json",
		}
	}

	changed := 0
	for _, c := range res.Changes {
		if c.Action != "unchanged" {
			changed++
		}
	}

	switch {
	case len(res.Drift) > 0:
		return Check{
			Name:   "configuration files",
			Status: Warn,
			Detail: fmt.Sprintf("%d file(s) would change; %d entries exist on this server but not in the panel",
				changed, countDrift(res)),
			Hint:    "a sync would drop those entries (it keeps a copy of the file first)",
			Command: "mailx-admin adopt --dry-run",
		}
	case changed > 0:
		return Check{
			Name:    "configuration files",
			Status:  Warn,
			Detail:  fmt.Sprintf("%d file(s) differ from the database", changed),
			Hint:    "the panel has not finished syncing, or the files were edited by hand",
			Command: "mailx-admin reconcile",
		}
	}
	return Check{Name: "configuration files", Status: OK, Detail: "every managed file matches the database"}
}

func countDrift(res *reconciler.Result) int {
	n := 0
	for _, d := range res.Drift {
		n += d.Count
	}
	return n
}

// validationCheck runs the daemons' own validators. Both are read-only
// (`postfix check` reads the configuration, `doveconf -n` prints it normalized),
// so they are safe on a live server.
func validationCheck(ctx context.Context, opts Options) Check {
	if opts.Config == nil {
		return Check{}
	}

	type validator struct {
		name string
		args []string
	}
	validators := []validator{
		{name: "postfix", args: []string{"check"}},
		{name: "doveconf", args: []string{"-n"}},
	}

	var checked, missing []string
	for _, v := range validators {
		if _, err := exec.LookPath(v.name); err != nil {
			missing = append(missing, v.name)
			continue
		}
		if err := execx.Run(ctx, checkTimeout, v.name, v.args...); err != nil {
			return Check{
				Name:    "daemon validation",
				Status:  Fail,
				Detail:  err.Error(),
				Hint:    "the daemons would refuse to start with the configuration on disk",
				Command: strings.Join(append([]string{v.name}, v.args...), " "),
			}
		}
		checked = append(checked, v.name)
	}

	if len(checked) == 0 {
		return Check{
			Name:   "daemon validation",
			Status: Warn,
			Detail: "no validator available on this host (" + strings.Join(missing, ", ") + ")",
			Hint:   "run doctor on the mail server itself",
		}
	}
	return Check{
		Name:   "daemon validation",
		Status: OK,
		Detail: "accepted by " + strings.Join(checked, " and "),
	}
}
