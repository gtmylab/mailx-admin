package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/auth"
)

func cmdUser() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage admin panel users",
	}
	cmd.AddCommand(cmdUserCreate(), cmdUserPasswd(), cmdUserList())
	return cmd
}

func cmdUserCreate() *cobra.Command {
	var (
		cfgPath string
		role    string
	)
	cmd := &cobra.Command{
		Use:   "create <username>",
		Short: "Create a new admin panel user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, _, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			username := args[0]

			fmt.Print("Password: ")
			var pw string
			fmt.Scanln(&pw)
			if len(pw) < 8 {
				return fmt.Errorf("password must be at least 8 characters")
			}

			hash, err := auth.HashPassword(pw)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			_, err = database.DB.ExecContext(ctx, `
                INSERT INTO admin_users (username, password_hash, role)
                VALUES (?, ?, ?)
            `, username, hash, role)
			if err != nil {
				return fmt.Errorf("create admin user: %w", err)
			}

			fmt.Printf("Admin user %q created with role %q\n", username, role)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().StringVar(&role, "role", "admin", "role: admin or readonly")
	return cmd
}

func cmdUserPasswd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "passwd <username>",
		Short: "Change an admin user's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, _, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			fmt.Print("New password: ")
			var pw string
			fmt.Scanln(&pw)
			if len(pw) < 8 {
				return fmt.Errorf("password must be at least 8 characters")
			}

			hash, err := auth.HashPassword(pw)
			if err != nil {
				return err
			}

			ctx := context.Background()
			res, err := database.DB.ExecContext(ctx, `
                UPDATE admin_users SET password_hash = ? WHERE username = ?
            `, hash, args[0])
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				return fmt.Errorf("no such user: %s", args[0])
			}
			fmt.Println("Password updated.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	return cmd
}

func cmdUserList() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List admin panel users",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, _, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			rows, err := database.DB.QueryContext(context.Background(),
				`SELECT id, username, role, active, COALESCE(last_login, '') FROM admin_users ORDER BY username`)
			if err != nil {
				return err
			}
			defer rows.Close()

			fmt.Printf("%-4s %-20s %-10s %-8s %s\n", "ID", "USERNAME", "ROLE", "ACTIVE", "LAST LOGIN")
			for rows.Next() {
				var id int64
				var username, role, lastLogin string
				var active int
				if err := rows.Scan(&id, &username, &role, &active, &lastLogin); err != nil {
					continue
				}
				fmt.Printf("%-4d %-20s %-10s %-8d %s\n", id, username, role, active, lastLogin)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	return cmd
}
