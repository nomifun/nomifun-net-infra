package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func validateDesktopBootstrapURL(raw string, dev bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimRight(u.Path, "/") != "/api/bootstrap/desktop/v2" {
		return fmt.Errorf("-desktop-bootstrap-url 必须是完整且不含凭据的 /api/bootstrap/desktop/v2 URL")
	}
	if u.Scheme == "https" && !loopbackHost(u.Hostname()) {
		return nil
	}
	if dev && (u.Scheme == "http" || u.Scheme == "https") && loopbackHost(u.Hostname()) {
		return nil
	}
	return errors.New("公共 Desktop bootstrap 必须使用 HTTPS；本机 HTTP 测试需显式 -desktop-dev-insecure")
}

func (rt *runtime) DesktopPreflight() console.DesktopPreflight {
	out := console.DesktopPreflight{ProtocolVersion: 2, BootstrapURL: rt.desktopBootstrapURL, DefaultBusinessURL: rt.desktopBusinessURL, Ready: true, Checks: []console.DesktopCheck{}}
	add := func(code string, ok bool, msg string) {
		out.Checks = append(out.Checks, console.DesktopCheck{Code: code, OK: ok, Message: msg})
		out.Ready = out.Ready && ok
	}
	add("bootstrap_url", rt.desktopBootstrapURL != "" && validateDesktopBootstrapURL(rt.desktopBootstrapURL, rt.desktopDevInsecure) == nil, "显式公共配对地址必须指向本 Relay；管理浏览器地址不自动作为配对地址")
	host, carrierPort, err := net.SplitHostPort(rt.bindAddr)
	parsedPort, portErr := strconv.ParseUint(carrierPort, 10, 16)
	validCarrier := err == nil && portErr == nil && parsedPort != 0 && host != ""
	if ip, err := netip.ParseAddr(host); err == nil {
		validCarrier = validCarrier && !ip.IsUnspecified() && (rt.desktopDevInsecure || (!ip.IsLoopback() && !ip.IsPrivate()))
	}
	add("carrier_address", validCarrier, "代理端承载使用 -advertise 明确指定的可达 host:port；公网部署不能使用容器网段")
	if rt.desktopDevInsecure {
		add("dev_mode", true, "仅本机 HTTP 测试模式；结果不代表公网 TLS、DNS 或手机验收")
	} else {
		rt.mu.RLock()
		shared := rt.shared
		rt.mu.RUnlock()
		add("shared_https", shared != nil && shared.tlsOn && rt.acme != nil && !rt.acme.IsStaging(), "生产连接需要启用 -shared HTTPS 与生产 ACME；配置预检不证明公网证书已签发")
	}
	return out
}

func (rt *runtime) CreateDesktopInviteV2(ctx context.Context, ttl time.Duration, req console.DesktopInviteV2Request) (console.DesktopPairingInviteResponse, error) {
	rt.desktopInviteMu.Lock()
	defer rt.desktopInviteMu.Unlock()
	if !rt.DesktopPreflight().Ready {
		return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：请检查公共配对地址、承载地址和 HTTPS 部署", console.ErrDesktopPrecondition)
	}
	business := strings.TrimRight(strings.TrimSpace(req.BusinessURL), "/")
	if business == "" {
		business = rt.desktopBusinessURL
	}
	tlsMode := tunnel.TLSGateway
	if rt.desktopDevInsecure && business == "" {
		port, err := availableDesktopPort(req.ListenPort)
		if err != nil {
			return console.DesktopPairingInviteResponse{}, err
		}
		business = desktopTunnelURL("127.0.0.1", port)
	}
	if err := validateDesktopBusinessURL(business); err != nil || business == "" {
		return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：请填写每台 Desktop 独立的 HTTPS origin", console.ErrDesktopPrecondition)
	}
	u, _ := url.Parse(business)
	u.Host = strings.ToLower(u.Host)
	business = u.String()
	port := uint16(443)
	if u.Port() != "" {
		value, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || value == 0 {
			return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：业务端口无效", console.ErrDesktopPrecondition)
		}
		port = uint16(value)
	}
	if u.Scheme == "http" && rt.desktopDevInsecure && loopbackHost(u.Hostname()) {
		tlsMode = tunnel.TLSPassthrough
		if u.Port() == "" {
			port = 80
		}
		if req.ListenPort != 0 && req.ListenPort != port {
			return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：HTTP 业务地址与公开端口不一致", console.ErrDesktopPrecondition)
		}
		if _, err := availableDesktopPort(port); err != nil {
			return console.DesktopPairingInviteResponse{}, err
		}
	} else {
		_, ipErr := netip.ParseAddr(u.Hostname())
		localTLS := rt.desktopDevInsecure && loopbackHost(u.Hostname())
		if u.Scheme != "https" || (!localTLS && (loopbackHost(u.Hostname()) || ipErr == nil || !desktopDNSName(u.Hostname()))) || (!rt.desktopDevInsecure && req.ListenPort != 0) {
			return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：生产业务入口需要独立的 HTTPS 域名", console.ErrDesktopPrecondition)
		}
		rt.mu.RLock()
		shared := rt.shared
		rt.mu.RUnlock()
		if shared == nil || !shared.tlsOn || shared.port != port {
			return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：HTTPS 入口端口必须与 -shared 一致", console.ErrDesktopPrecondition)
		}
	}
	existing, err := rt.db.ListDesktopConnections(ctx, tunnel.DefaultTenantID)
	if err != nil {
		return console.DesktopPairingInviteResponse{}, err
	}
	for _, invite := range existing {
		if invite.RevokedAt.IsZero() && (!invite.UsedAt.IsZero() || invite.ExpiresAt.After(time.Now())) && strings.EqualFold(invite.PublicHostname, u.Hostname()) && invite.PublicPort == port {
			return console.DesktopPairingInviteResponse{}, fmt.Errorf("%w：该公开地址已分配给另一台 Desktop", store.ErrConflict)
		}
	}
	token, invite, err := rt.db.CreatePairingInvite(ctx, store.PairingInviteSpec{TenantID: tunnel.DefaultTenantID, Scopes: []string{console.DesktopBootstrapScope}, Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: console.DesktopBackendAddrV2}, PublicHostname: u.Hostname(), PublicPort: port, TLS: tlsMode, TTL: ttl, Note: req.Note, BootstrapVersion: 2, BusinessURL: business})
	if err != nil {
		return console.DesktopPairingInviteResponse{}, err
	}
	return console.DesktopPairingInviteResponse{ID: invite.ID, Token: token, Relay: rt.bindAddr, Pin: rt.pin, ListenPort: port, ExpiresAt: invite.ExpiresAt, ProtocolVersion: 2, BootstrapURL: rt.desktopBootstrapURL, BusinessURL: business}, nil
}

func desktopDNSName(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func availableDesktopPort(port uint16) (uint16, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return 0, fmt.Errorf("%w：公开端口被占用：%v", console.ErrDesktopPrecondition, err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func (rt *runtime) BootstrapDesktopV2(ctx context.Context, token, attempt string) (console.DesktopBootstrapV2Response, error) {
	invite, err := rt.db.PeekPairingInvite(ctx, token)
	if err != nil {
		return console.DesktopBootstrapV2Response{}, err
	}
	if invite.BootstrapVersion != 2 {
		return console.DesktopBootstrapV2Response{}, store.ErrPairingInviteVersionMismatch
	}
	t := &tunnel.Tunnel{Kind: tunnel.KindService, TLS: invite.TLS, Exposure: tunnel.ExposurePort, L4: tunnel.L4TCP, ListenPort: invite.PublicPort, Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: console.DesktopBackendAddrV2}}
	if invite.TLS == tunnel.TLSGateway {
		t.Exposure = tunnel.ExposureShared
		t.ListenPort = 0
		t.Router = &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{invite.PublicHostname}, HostRewrite: console.DesktopBackendAddrV2}
	}
	invite, enrol, control, err := rt.db.ProvisionDesktop(ctx, token, attempt, store.PairingInviteRedeemRequest{TenantID: tunnel.DefaultTenantID, Scopes: []string{console.DesktopBootstrapScope}, Backend: t.Backend, UsedBy: "desktop-bootstrap-v2"}, t, rt.desktopEnrolTTL)
	if err != nil {
		return console.DesktopBootstrapV2Response{}, err
	}
	applyErr := rt.ApplyTunnels()
	if fresh, err := rt.db.GetTunnel(ctx, t.ID); err == nil {
		t = fresh
	}
	state := rt.connectionProjection(ctx, invite)
	if applyErr != nil && state.State != "error" {
		state.State = "error"
		state.Reason = "配置已保存，入口应用失败；用同一配对尝试重试或检查 Relay 日志"
	}
	u, _ := url.Parse(rt.desktopBootstrapURL)
	u.Path = "/api/desktop-connections/" + invite.ID
	l2Port := uint16(0)
	rt.mu.RLock()
	if rt.shared != nil {
		l2Port = rt.shared.port
	}
	rt.mu.RUnlock()
	return console.DesktopBootstrapV2Response{ProtocolVersion: 2, L2Port: l2Port, ControlURL: u.String(), ControlToken: control, State: state.State, Reason: state.Reason, DesktopBootstrapResponse: console.DesktopBootstrapResponse{InviteID: invite.ID, Relay: rt.bindAddr, BusinessURL: invite.BusinessURL, ProbeURL: invite.BusinessURL, Pin: rt.pin, EnrolToken: enrol, EnrolExpiresAt: invite.EnrolExpiresAt, InstallCmd: fmt.Sprintf("nfagent -relay %s -pin %s -token %s", rt.bindAddr, rt.pin, enrol), Tunnel: t}}, nil
}

func (rt *runtime) connectionProjection(ctx context.Context, invite *store.PairingInvite) console.DesktopConnection {
	out := console.DesktopConnection{ProtocolVersion: 2, InviteID: invite.ID, Note: invite.Note, BusinessURL: invite.BusinessURL, TunnelID: invite.TunnelID, AgentID: invite.AgentID, State: "waiting", Reason: "等待 Desktop 兑换邀请", Revoked: !invite.RevokedAt.IsZero()}
	if out.Revoked {
		out.State = "revoked"
		out.Reason = "连接已撤销"
		return out
	}
	if invite.UsedAt.IsZero() {
		if !invite.ExpiresAt.After(time.Now()) {
			out.State = "expired"
			out.Reason = "邀请已过期，请生成新邀请"
		}
		return out
	}
	t, err := rt.db.GetTunnel(ctx, invite.TunnelID)
	if err != nil {
		out.State = "error"
		out.Reason = "连接隧道不存在，请撤销并重新连接"
		return out
	}
	out.State = "pending"
	out.Reason = "配置已保存，等待网络代理端上线"
	if t.State == tunnel.StateError || t.State == tunnel.StateRejectedByAgent {
		out.State = "error"
		out.Reason = t.StateReason
		return out
	}
	if t.State == tunnel.StateActive {
		if sess, ok := rt.SessionFor(invite.AgentID); ok && sess.Alive() {
			out.State = "transport_ready"
			out.Reason = "网络代理端和隧道已就绪；Desktop 与手机仍须验证业务入口和身份"
		}
	}
	return out
}

func (rt *runtime) ListDesktopConnections(ctx context.Context) ([]console.DesktopConnection, error) {
	list, err := rt.db.ListDesktopConnections(ctx, tunnel.DefaultTenantID)
	if err != nil {
		return nil, err
	}
	out := make([]console.DesktopConnection, 0, len(list))
	for _, invite := range list {
		out = append(out, rt.connectionProjection(ctx, invite))
	}
	return out, nil
}

func (rt *runtime) DesktopConnection(ctx context.Context, id, token string, admin bool) (console.DesktopConnection, error) {
	if admin {
		list, err := rt.db.ListDesktopConnections(ctx, tunnel.DefaultTenantID)
		if err != nil {
			return console.DesktopConnection{}, err
		}
		for _, invite := range list {
			if invite.ID == id {
				return rt.connectionProjection(ctx, invite), nil
			}
		}
		return console.DesktopConnection{}, store.ErrNotFound
	}
	invite, err := rt.db.DesktopConnection(ctx, id, token)
	if err != nil {
		return console.DesktopConnection{}, err
	}
	return rt.connectionProjection(ctx, invite), nil
}

func (rt *runtime) RevokeDesktopConnection(ctx context.Context, id, token string, admin bool) (console.DesktopConnection, error) {
	var invite *store.PairingInvite
	var err error
	if admin {
		invite, err = rt.db.RevokeDesktopConnectionAsAdmin(ctx, id)
	} else {
		invite, err = rt.db.RevokeDesktopConnection(ctx, id, token)
	}
	if err != nil {
		return console.DesktopConnection{}, err
	}
	return rt.finishDesktopRevocation(ctx, invite)
}

func (rt *runtime) CancelDesktopBootstrap(ctx context.Context, token, attempt string) (console.DesktopConnection, error) {
	invite, err := rt.db.CancelDesktopBootstrap(ctx, token, attempt)
	if err != nil {
		return console.DesktopConnection{}, err
	}
	return rt.finishDesktopRevocation(ctx, invite)
}

func (rt *runtime) finishDesktopRevocation(ctx context.Context, invite *store.PairingInvite) (console.DesktopConnection, error) {
	rt.KickAgent(invite.AgentID)
	if err := rt.ApplyTunnels(); err != nil {
		rt.log.Warn("Desktop 连接已撤销，但运行时应用未完成", "invite_id", invite.ID, "err", err)
		return console.DesktopConnection{}, err
	}
	return rt.connectionProjection(ctx, invite), nil
}
