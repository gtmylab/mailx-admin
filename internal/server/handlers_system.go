package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

const systemCmdTimeout = 30 * time.Second

// ---- Firewall --------------------------------------------------------------

type firewallStatus struct {
	Backend string // "ufw", "firewalld", "none"
	Active  bool
	Output  string
}

func (s *Server) firewallBackend() string {
	if _, err := execx.Output(context.Background(), systemCmdTimeout, "ufw", "status"); err == nil {
		return "ufw"
	}
	if _, err := execx.Output(context.Background(), systemCmdTimeout, "firewall-cmd", "--state"); err == nil {
		return "firewalld"
	}
	return "none"
}

func (s *Server) firewallStatus(ctx context.Context) (firewallStatus, error) {
	st := firewallStatus{Backend: s.firewallBackend()}
	switch st.Backend {
	case "ufw":
		out, err := execx.Output(ctx, systemCmdTimeout, "ufw", "status", "verbose")
		if err != nil {
			return st, err
		}
		st.Output = string(out)
		st.Active = strings.Contains(strings.ToLower(st.Output), "status: active")
	case "firewalld":
		out, err := execx.Output(ctx, systemCmdTimeout, "firewall-cmd", "--list-all")
		if err != nil {
			return st, err
		}
		st.Output = string(out)
		st.Active = true
	}
	return st, nil
}

func (s *Server) handleFirewallPage(w http.ResponseWriter, r *http.Request) {
	st, _ := s.firewallStatus(r.Context())
	s.render(w, 200, "firewall.html", s.newPageData(w, r, "Firewall", "firewall", map[string]any{
		"Status": st,
	}))
}

func (s *Server) handleFirewallAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	action := r.FormValue("action")
	port := strings.TrimSpace(r.FormValue("port"))
	backend := s.firewallBackend()
	ctx := r.Context()

	if backend == "none" {
		s.renderFormError(w, "No supported firewall found (ufw or firewalld). Install one first.")
		return
	}

	var out []byte
	var err error
	switch action {
	case "enable":
		if backend == "ufw" {
			out, err = execx.Output(ctx, systemCmdTimeout, "ufw", "--force", "enable")
		} else if backend == "firewalld" {
			out, err = execx.Output(ctx, systemCmdTimeout, "systemctl", "enable", "--now", "firewalld")
		}
	case "disable":
		if backend == "ufw" {
			out, err = execx.Output(ctx, systemCmdTimeout, "ufw", "--force", "disable")
		} else if backend == "firewalld" {
			out, err = execx.Output(ctx, systemCmdTimeout, "systemctl", "disable", "--now", "firewalld")
		}
	case "allow", "deny":
		if port == "" {
			s.renderFormError(w, "Port is required")
			return
		}
		if backend == "ufw" {
			verb := "allow"
			if action == "deny" {
				verb = "delete allow"
			}
			out, err = ufwPortRule(ctx, verb, port)
		} else if backend == "firewalld" {
			op := "--add-port"
			if action == "deny" {
				op = "--remove-port"
			}
			out, err = execx.Output(ctx, systemCmdTimeout, "firewall-cmd", "--permanent", op, port+"/tcp")
			if err == nil {
				_, _ = execx.Output(ctx, systemCmdTimeout, "firewall-cmd", "--reload")
			}
		}
	default:
		s.renderFormError(w, "Unknown action")
		return
	}

	if err != nil {
		s.renderFormError(w, fmt.Sprintf("Firewall %s failed: %v", action, err))
		return
	}
	s.renderPartial(w, "firewall_result", map[string]any{"Output": strings.TrimSpace(string(out))})
}

func ufwPortRule(ctx context.Context, verb, port string) ([]byte, error) {
	if verb == "delete allow" {
		return execx.Output(ctx, systemCmdTimeout, "ufw", "delete", "allow", port+"/tcp")
	}
	return execx.Output(ctx, systemCmdTimeout, "ufw", "allow", port+"/tcp")
}

// ---- Networking ------------------------------------------------------------

type networkInterface struct {
	Name    string
	Address string
}

func (s *Server) handleNetworkingPage(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.networkInterfaces(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to read network interfaces: "+err.Error())
		return
	}
	s.render(w, 200, "networking.html", s.newPageData(w, r, "Networking", "networking", map[string]any{
		"Interfaces": ifaces,
	}))
}

func (s *Server) networkInterfaces(ctx context.Context) ([]networkInterface, error) {
	out, err := execx.Output(ctx, systemCmdTimeout, "ip", "-o", "addr", "show")
	if err != nil {
		return nil, err
	}
	var out2 []networkInterface
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || (fields[2] != "inet" && fields[2] != "inet6") {
			continue
		}
		out2 = append(out2, networkInterface{Name: strings.TrimSuffix(fields[1], ":"), Address: fields[3]})
	}
	return out2, nil
}

func (s *Server) handleNetworkPing(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if host == "" {
		s.renderFormError(w, "Host is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := execx.Output(ctx, 20*time.Second, "ping", "-c", "4", host)
	if err != nil {
		s.renderPartial(w, "network_test_result", map[string]any{"Output": fmt.Sprintf("ping %s failed: %v\n%s", host, err, out)})
		return
	}
	s.renderPartial(w, "network_test_result", map[string]any{"Output": string(out)})
}

// handleNetworkAddIP adds an address to an interface with `ip addr add`. The
// address must already be routed to this host by the provider; the panel only
// configures the OS side. Persistence (netplan/ifcfg) is left to the operator.
func (s *Server) handleNetworkAddIP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	iface := strings.TrimSpace(r.FormValue("interface"))
	cidr := strings.TrimSpace(r.FormValue("cidr"))
	if iface == "" || cidr == "" {
		s.renderFormError(w, "Interface and address are required")
		return
	}
	ip := strings.SplitN(cidr, "/", 2)[0]
	if net.ParseIP(ip) == nil {
		s.renderFormError(w, "That is not a valid IP address")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), systemCmdTimeout)
	defer cancel()
	out, err := execx.Output(ctx, systemCmdTimeout, "ip", "addr", "add", cidr, "dev", iface)
	if err != nil {
		s.renderPartial(w, "network_add_result", map[string]any{
			"Error": fmt.Sprintf("Failed to add %s to %s: %v", cidr, iface, err),
			"Out":   string(out),
		})
		return
	}
	s.renderPartial(w, "network_add_result", map[string]any{
		"Message": fmt.Sprintf("Added %s to %s (non-persistent: configure netplan for a permanent address).", cidr, iface),
	})
}
