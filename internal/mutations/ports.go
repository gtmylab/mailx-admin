package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/ports"
)

type CreatePortInput struct {
	Port        int
	TLSMode     string
	RequireSASL bool
	Description string
}

func (s *Service) CreatePort(ctx context.Context, actor Actor, in CreatePortInput) (*Result, error) {
	if in.TLSMode == "" {
		in.TLSMode = "may"
	}
	if in.TLSMode != "may" && in.TLSMode != "encrypt" && in.TLSMode != "none" {
		return nil, fmt.Errorf("%w: invalid TLS mode", ErrInvalidInput)
	}

	// Fetch existing for validation
	existing, err := s.listPortListeners(ctx)
	if err != nil {
		return nil, err
	}
	candidate := models.PortListener{Port: in.Port, TLSMode: in.TLSMode}
	if err := ports.Validate(candidate, existing); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
	}

	// Check the port isn't already bound by another process
	if err := ports.CheckPortAvailable(in.Port); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrConflict, err.Error())
	}

	res, err := s.Apply(ctx, actor, "port.create", map[string]any{
		"port":     in.Port,
		"tls_mode": in.TLSMode,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
            INSERT INTO port_listeners (port, service, tls_mode, require_sasl, description, enabled)
            VALUES (?, 'smtpd', ?, ?, ?, 1)
        `, in.Port, in.TLSMode, boolInt(in.RequireSASL), in.Description)
		return err
	})
	return res, err
}

func (s *Service) DeletePort(ctx context.Context, actor Actor, id int64) (*Result, error) {
	var port int
	err := s.db.QueryRowContext(ctx, `SELECT port FROM port_listeners WHERE id = ?`, id).Scan(&port)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: port not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	res, err := s.Apply(ctx, actor, "port.delete", map[string]any{
		"port": port,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM port_listeners WHERE id = ?`, id)
		return err
	})
	return res, err
}

func (s *Service) TogglePort(ctx context.Context, actor Actor, id int64, enabled bool) (*Result, error) {
	res, err := s.Apply(ctx, actor, "port.toggle", map[string]any{
		"id":      id,
		"enabled": enabled,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE port_listeners SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
		return err
	})
	return res, err
}

func (s *Service) listPortListeners(ctx context.Context) ([]models.PortListener, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, port, service, tls_mode, require_sasl, COALESCE(description,''), enabled
        FROM port_listeners ORDER BY port
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.PortListener
	for rows.Next() {
		var l models.PortListener
		var sasl, enabled int
		if err := rows.Scan(&l.ID, &l.Port, &l.Service, &l.TLSMode, &sasl, &l.Description, &enabled); err != nil {
			continue
		}
		l.RequireSASL = sasl == 1
		l.Enabled = enabled == 1
		out = append(out, l)
	}
	return out, rows.Err()
}

// Exported for the reconciler
func (s *Service) ListPortListeners(ctx context.Context) ([]models.PortListener, error) {
	return s.listPortListeners(ctx)
}
