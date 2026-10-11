package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// routes 注册所有路由。
//
// 用 stdlib 的 ServeMux（Go 1.22+ 支持方法与通配路由），不引入 chi/gin：
// 后者的私有 context 会污染每个签名，而我们的服务器同时还是数据面网关，
// 需要裸 net.Conn。
func (s *Server) routes() {
	m := s.mux

	// 不需要鉴权的端点。
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /api/setup", s.handleSetupState)
	m.HandleFunc("POST /api/setup", s.handleSetup)
	m.HandleFunc("POST /api/login", s.handleLogin)

	// 需要鉴权。
	m.HandleFunc("POST /api/logout", s.requireAuth(s.handleLogout))
	m.HandleFunc("GET /api/me", s.requireAuth(s.handleMe))
	m.HandleFunc("POST /api/password", s.requireAuth(s.handleChangePassword))

	m.HandleFunc("GET /api/snapshot", s.requireAuth(s.handleSnapshot))
	m.HandleFunc("GET /api/events", s.requireAuth(s.handleEventStream))
	m.HandleFunc("GET /api/events/recent", s.requireAuth(s.handleRecentEvents))

	m.HandleFunc("GET /api/tunnels", s.requireAuth(s.handleListTunnels))
	m.HandleFunc("POST /api/tunnels", s.requireAuth(s.handleCreateTunnel))
	m.HandleFunc("POST /api/tunnels:validate", s.requireAuth(s.handleValidateTunnel))
	m.HandleFunc("GET /api/tunnels/{id}", s.requireAuth(s.handleGetTunnel))
	m.HandleFunc("PUT /api/tunnels/{id}", s.requireAuth(s.handleUpdateTunnel))
	m.HandleFunc("DELETE /api/tunnels/{id}", s.requireAuth(s.handleDeleteTunnel))
	m.HandleFunc("GET /api/tunnels/{id}/samples", s.requireAuth(s.handleTunnelSamples))

	// 学习模式：观测到的来源地址（只读；两个写动作走 handleTunnelVerb）。
	m.HandleFunc("GET /api/tunnels/{id}/learned-sources", s.requireAuth(s.handleLearnedSources))

	m.HandleFunc("GET /api/agents", s.requireAuth(s.handleListAgents))
	m.HandleFunc("DELETE /api/agents/{id}", s.requireAuth(s.handleRevokeAgent))
	m.HandleFunc("POST /api/enrol-tokens", s.requireAuth(s.handleIssueEnrolToken))

	// 动词型端点。**不能**写成 "/api/tunnels/{id}:test" ——
	// Go 的 ServeMux 要求通配符占满整个路径段，那样写会在注册时 panic，
	// 于是中继直接起不来而不是返回 404。动词在处理器里切。
	m.HandleFunc("POST /api/tunnels/{id}", s.requireAuth(s.handleTunnelVerb))
	m.HandleFunc("POST /api/agents/{id}", s.requireAuth(s.handleAgentVerb))
	m.HandleFunc("POST /api/tunnels:preview", s.requireAuth(s.handlePreviewTunnel))
	m.HandleFunc("GET /api/settings", s.requireAuth(s.handleSettings))
	m.HandleFunc("POST /api/pairing-invites", s.requireAuth(s.handleCreateDesktopPairingInvite))

	// Desktop bootstrap intentionally is not behind the administrator session:
	// the one-time invite is the only credential for this narrow operation.
	m.HandleFunc("POST /api/bootstrap/desktop", s.handleBootstrapDesktop)
	m.HandleFunc("GET /api/desktop/preflight", s.requireAuth(s.handleDesktopPreflight))
	m.HandleFunc("POST /api/pairing-invites/v2", s.requireAuth(s.handleCreateDesktopInviteV2))
	m.HandleFunc("POST /api/bootstrap/desktop/v2", s.handleBootstrapDesktopV2)
	m.HandleFunc("POST /api/bootstrap/desktop/v2:cancel", s.handleCancelDesktopBootstrap)
	m.HandleFunc("GET /api/desktop-connections", s.requireAuth(s.handleListDesktopConnections))
	m.HandleFunc("GET /api/desktop-connections/{id}", s.handleDesktopConnection)
	m.HandleFunc("DELETE /api/desktop-connections/{id}", s.handleDesktopConnection)

	// 声明式整份配置。两个端点而不是一个带 dry_run 标志的端点：
	// 「先看看会发生什么」与「去做」是两个动作，而 apply 能删隧道。
	m.HandleFunc("POST /api/config:validate", s.requireAuth(s.handleValidateConfig))
	m.HandleFunc("POST /api/config:apply", s.requireAuth(s.handleApplyConfig))
	// 支持包。GET 而不是 POST：它是一次读取，且前端用 <a download> 直接触发
	// —— 那个元素只能发 GET。留痕在处理器里做（外发动作必须可追溯）。
	m.HandleFunc("GET /api/diagnostics/support-bundle", s.requireAuth(s.handleSupportBundle))

	m.HandleFunc("GET /api/turn/allocations", s.requireAuth(s.handleTurnAllocations))
	m.HandleFunc("POST /api/turn/credentials", s.requireAuth(s.handleMintTurnCredential))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// /healthz 故意不鉴权 —— 编排系统的探针拿不到凭据。
	// 它也故意不泄露任何内部状态。
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── 首启与鉴权 ──────────────────────────────────────────────────────────────

// SetupState 告诉前端是否需要走首启引导。
type SetupState struct {
	NeedsSetup bool `json:"needs_setup"`
}

func (s *Server) handleSetupState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, SetupState{NeedsSetup: !s.db.HasAdmin(r.Context())})
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// MinPasswordLen 是管理员密码的最小长度。
//
// 12 位是在「用户愿意输」与「离线爆破成本」之间的折中；配合 argon2id
// 的 64MiB 内存开销，这个长度的爆破成本已经足够高。
const MinPasswordLen = 12

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	// 首启同样限速：它未鉴权，而且会跑一次 argon2（分配 64 MiB）。
	// 首启只能成功一次，但**失败**的尝试次数没有上限。
	rv, retry := s.guard.allow(r)
	if rv == nil {
		if s.guard.shouldLogThrottle(r) {
			s.log.Warn("首启被限速（源 IP 尝试过于频繁）", "remote", r.RemoteAddr)
		}
		writeThrottled(w, retry)
		return
	}

	// 首启只能做一次。否则任何人都能在管理员创建后再覆盖一个自己的账号。
	if s.db.HasAdmin(r.Context()) {
		writeError(w, http.StatusConflict, "already_setup", "已完成初始化，请直接登录")
		return
	}

	var req setupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体解析失败")
		return
	}
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, APIError{
			Code: "invalid", Message: "用户名不能为空",
			Fields: []FieldError{{Path: "username", Message: "不能为空"}},
		})
		return
	}
	if len(req.Password) < MinPasswordLen {
		writeJSON(w, http.StatusBadRequest, APIError{
			Code: "invalid", Message: "密码太短",
			Fields: []FieldError{{Path: "password",
				Message: "至少 " + strconv.Itoa(MinPasswordLen) + " 个字符"}},
		})
		return
	}

	if err := s.db.CreateAdmin(r.Context(), req.Username, req.Password, false); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	rv.succeeded() // 成功的首启不该占配额

	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindConsoleLogin, Level: store.LevelInfo,
		Message: "完成首启初始化", Actor: req.Username,
	})
	s.issueSession(w, r, req.Username, false)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 是登录成功的响应。
type LoginResponse struct {
	Username string `json:"username"`
	// CSRFToken 前端必须回显在 X-NFR-CSRF 头里。
	CSRFToken string `json:"csrf_token"`
	// MustRotate 为 true 时前端必须先跳改密页。
	MustRotate bool `json:"must_rotate"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 限速在**解析请求体之前**：一个正在爆破的人不该让我们先做任何工作。
	// 进门即扣（不是「先查再扣」）—— 先查再扣在并发下等于没限：
	// N 个请求同时看到「还有额度」，然后 N 个一起扣。
	rv, retry := s.guard.allow(r)
	if rv == nil {
		if s.guard.shouldLogThrottle(r) {
			s.log.Warn("登录被限速（源 IP 尝试过于频繁）", "remote", r.RemoteAddr)
			_ = s.db.AppendEvent(r.Context(), store.Event{
				Kind: store.KindConsoleLoginThrottled, Level: store.LevelWarn,
				Message: "登录尝试被限速（同一源 IP 过于频繁）",
			})
		}
		writeThrottled(w, retry)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体解析失败")
		return
	}

	mustRotate, ok, err := s.db.VerifyAdmin(r.Context(), req.Username, req.Password)
	if err != nil {
		// 密码哈希排不上队（并发闸满）。这**不是**凭据错误：回 401 会让正常
		// 用户在一次洪水期间看到「密码错误」而去查密码，查错方向；
		// 而且它会让这次失败被记成一次登录失败事件。
		//
		// 503 + Retry-After 是唯一诚实的答案：服务器暂时做不了这件事。
		// 不记 login_failed 事件 —— 洪水期间那会把事件表刷成噪音，
		// 而真正该被记的是「有人在打这台机器」，不是「某人密码错了」。
		s.log.Warn("登录被并发闸拒绝（密码哈希繁忙）", "user", req.Username, "err", err)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "hash_busy",
			"服务器正忙（密码校验队列已满），请稍后重试。这不是密码错误。")
		return
	}
	if !ok {
		_ = s.db.AppendEvent(r.Context(), store.Event{
			Kind: store.KindConsoleLoginBad, Level: store.LevelWarn,
			Message: "登录失败", Actor: req.Username,
		})
		// 不区分「用户不存在」与「密码错误」——那会变成一个用户名枚举接口。
		// VerifyAdmin 内部已做等时处理。
		writeError(w, http.StatusUnauthorized, "bad_credentials", "用户名或密码错误")
		return
	}

	// 成功了就清掉这个源 IP 的失败预算：限速的目标是**失败的**尝试。
	// 不清的话，一个每天登录几十次的运维会被自己的正常使用逐步耗尽配额，
	// 然后在某个再普通不过的早上被自己的防护关在门外。
	rv.succeeded()

	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindConsoleLogin, Level: store.LevelInfo,
		Message: "登录成功", Actor: req.Username,
	})
	s.issueSession(w, r, req.Username, mustRotate)
}

func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, username string, mustRotate bool) {
	token, csrf, err := s.db.CreateSession(r.Context(), username, SessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "创建会话失败")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		// SameSite=Strict：控制台没有任何需要跨站携带 Cookie 的场景。
		// EasyTier 用的是 Lax（restful/mod.rs:223），那是不必要的放宽。
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})

	// CSRF 令牌也下发一个**可被脚本读取**的 Cookie（双提交 Cookie 模式）。
	//
	// # 为什么这不是把令牌泄露出去
	//
	// 双提交的安全性不来自「攻击者读不到令牌」，而来自「攻击者的页面
	// **读不到我们的 Cookie**」——同源策略。跨站请求虽然会自动带上
	// Cookie，却无法把它的值抄进请求头，于是「头与 Cookie 相等」这个
	// 条件跨站永远满足不了。所以这个 Cookie 必须 HttpOnly=false，
	// 那是设计要求而不是疏漏。会话 Cookie 仍然是 HttpOnly。
	//
	// # 为什么必须真的下发它
	//
	// CSRFCookieName 这个常量原本存在、前端也有 readCookie 兜底
	//（client.ts 的 `csrfToken || readCookie(CSRF_COOKIE)`），
	// 但服务端**从来没设过这个 Cookie** —— 于是那条兜底永远走不到，
	// 而它要兜的正是「刷新页面之后、/api/me 回来之前发出的写请求」。
	// 一个看起来存在的安全网，其实是空的。
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    csrf,
		Path:     "/",
		HttpOnly: false, // 前端要读它，见上面的说明
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})

	writeJSON(w, http.StatusOK, LoginResponse{
		Username: username, CSRFToken: csrf, MustRotate: mustRotate,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ *session) {
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		sum := sha256.Sum256([]byte(c.Value))
		_ = s.db.DeleteSession(r.Context(), hex.EncodeToString(sum[:]))
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.sessionCookieName(), Value: "", Path: "/",
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	// CSRF Cookie 也要清。留着它不会造成漏洞（会话已经没了），
	// 但会让下一个用户的浏览器带着上一个会话的令牌发请求，
	// 拿到一个「CSRF 校验失败」而不是「未登录」——错误信息指错方向。
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookieName, Value: "", Path: "/",
		HttpOnly: false, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *session) {
	writeJSON(w, http.StatusOK, LoginResponse{
		Username: sess.Username, CSRFToken: sess.CSRFToken,
	})
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *session) {
	var req changePasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体解析失败")
		return
	}
	// 改密必须验旧密码：否则一个被盗的会话 Cookie 就能永久锁定账号。
	_, ok, err := s.db.VerifyAdmin(r.Context(), sess.Username, req.Current)
	if err != nil {
		// 同 handleLogin：繁忙不是凭据错误。改密路径尤其要分清 ——
		// 把它报成「当前密码不正确」会让用户以为自己记错了口令。
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "hash_busy",
			"服务器正忙（密码校验队列已满），请稍后重试。这不是密码错误。")
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "bad_credentials", "当前密码不正确")
		return
	}
	if len(req.New) < MinPasswordLen {
		writeJSON(w, http.StatusBadRequest, APIError{
			Code: "invalid", Message: "新密码太短",
			Fields: []FieldError{{Path: "new",
				Message: "至少 " + strconv.Itoa(MinPasswordLen) + " 个字符"}},
		})
		return
	}
	if err := s.db.SetAdminPassword(r.Context(), sess.Username, req.New); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── 快照与事件 ──────────────────────────────────────────────────────────────

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, _ *session) {
	if s.snapshot == nil {
		writeJSON(w, http.StatusOK, Snapshot{})
		return
	}
	writeJSON(w, http.StatusOK, s.snapshot.Snapshot())
}

func (s *Server) handleRecentEvents(w http.ResponseWriter, r *http.Request, _ *session) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	sinceID, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	list, err := s.db.ListEvents(r.Context(), limit, sinceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if list == nil {
		list = []store.Event{}
	}
	writeJSON(w, http.StatusOK, list)
}

// ── 隧道 CRUD ───────────────────────────────────────────────────────────────

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request, _ *session) {
	list, err := s.db.ListTunnels(r.Context(), tunnel.DefaultTenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if list == nil {
		list = []*tunnel.Tunnel{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request, _ *session) {
	t, err := s.db.GetTunnel(r.Context(), r.PathValue("id"))
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// decodeTunnel 解析请求体里的隧道定义。
//
// **配置输入必须严格**：未知字段是错误。这与线协议上的宽容恰好相反 ——
// 线上要容忍未知字段以便演进，而配置里的未知字段几乎总是拼写错误，
// 静默忽略会让用户以为自己设置了某个选项。
func decodeTunnel(w http.ResponseWriter, r *http.Request) (*tunnel.Tunnel, error) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	var t tunnel.Tunnel
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// handleValidateTunnel 是 dry-run 校验端点。
//
// 前端在提交前调它，从而避免 frp store API 的那个缺陷：控制台接受一个
// 中继后来会拒绝的配置，表现为隧道进 error 相而不是写入时 400。
func (s *Server) handleValidateTunnel(w http.ResponseWriter, r *http.Request, _ *session) {
	t, err := decodeTunnel(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	t.Complete()
	if err := t.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{
			Code: "invalid", Message: "隧道定义不合法", Fields: fieldErrors(err),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	t, err := decodeTunnel(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if t.ID == "" {
		id, err := randomToken(6)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "生成 ID 失败")
			return
		}
		t.ID = "t-" + id
	}
	s.putTunnel(w, r, t, sess, store.KindTunnelCreated, "创建隧道")
}

func (s *Server) handleUpdateTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	t, err := decodeTunnel(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// URL 里的 ID 是权威的，防止请求体改 ID 造成越权改别的记录。
	t.ID = r.PathValue("id")
	if _, err := s.db.GetTunnel(r.Context(), t.ID); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	s.putTunnel(w, r, t, sess, store.KindTunnelUpdated, "更新隧道")
}

func (s *Server) putTunnel(
	w http.ResponseWriter, r *http.Request, t *tunnel.Tunnel,
	sess *session, kind, action string,
) {
	t.Complete()
	if err := t.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{
			Code: "invalid", Message: "隧道定义不合法", Fields: fieldErrors(err),
		})
		return
	}
	if err := s.db.PutTunnel(r.Context(), t); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}

	// 立即让运行时生效。校验已过，所以这里失败属于运行时问题（例如端口被
	// 进程外的东西占了），要如实报出来而不是假装成功。
	if s.snapshot != nil {
		if err := s.snapshot.ApplyTunnels(); err != nil {
			s.log.Error("应用隧道变更失败", "隧道", t.Slug, "err", err)
			writeJSON(w, http.StatusConflict, APIError{
				Code:    "apply_failed",
				Message: "配置已保存，但运行时应用失败：" + err.Error(),
			})
			return
		}
	}

	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: kind, Level: store.LevelInfo,
		Subject: t.Slug, Message: action, Actor: sess.Username,
	})
	s.hub.publish(Event{Type: "state", Data: map[string]any{"tunnel": t.ID}})
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	t, err := s.db.GetTunnel(r.Context(), id)
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	if err := s.db.DeleteTunnel(r.Context(), id); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	if s.snapshot != nil {
		if err := s.snapshot.ApplyTunnels(); err != nil {
			s.log.Error("删除后应用变更失败", "隧道", t.Slug, "err", err)
		}
	}
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindTunnelDeleted, Level: store.LevelWarn,
		Subject: t.Slug, Message: "删除隧道", Actor: sess.Username,
	})
	s.hub.publish(Event{Type: "state", Data: map[string]any{"tunnel": id, "deleted": true}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTunnelSamples(w http.ResponseWriter, r *http.Request, _ *session) {
	id := r.PathValue("id")
	// 默认最近 1 小时。
	to := time.Now()
	from := to.Add(-time.Hour)
	if v := r.URL.Query().Get("from"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			from = time.Unix(ts, 0)
		}
	}

	samples, err := s.db.QuerySamples(r.Context(), id, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if samples == nil {
		samples = []store.Sample{}
	}

	// 分位数从直方图算，而不是从样本表的均值猜。
	p50, _ := s.db.Quantile(r.Context(), id, from, to, 0.5)
	p95, _ := s.db.Quantile(r.Context(), id, from, to, 0.95)
	p99, _ := s.db.Quantile(r.Context(), id, from, to, 0.99)

	writeJSON(w, http.StatusOK, map[string]any{
		"samples": samples,
		"rtt": map[string]int64{
			"p50_us": p50.Microseconds(),
			"p95_us": p95.Microseconds(),
			"p99_us": p99.Microseconds(),
		},
	})
}

// ── Agent 与入网令牌 ────────────────────────────────────────────────────────

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request, _ *session) {
	// 优先用运行时快照：它含在线状态与承载梯级，而数据库只有注册信息。
	if s.snapshot != nil {
		snap := s.snapshot.Snapshot()
		if snap.Agents == nil {
			snap.Agents = []AgentStatus{}
		}
		writeJSON(w, http.StatusOK, snap.Agents)
		return
	}
	list, err := s.db.ListAgents(r.Context(), tunnel.DefaultTenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]AgentStatus, 0, len(list))
	for _, a := range list {
		out = append(out, AgentStatus{
			ID: a.ID, Hostname: a.Hostname, OS: a.OS, Arch: a.Arch,
			Version: a.Version, Revoked: a.Revoked, LastSeenAt: a.LastSeenAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	if err := s.db.RevokeAgent(r.Context(), id); err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindAgentRevoked, Level: store.LevelWarn,
		Subject: id, Message: "撤销代理端凭据", Actor: sess.Username,
	})
	s.hub.publish(Event{Type: "state", Data: map[string]any{"agent": id, "revoked": true}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type enrolTokenRequest struct {
	// TTLSeconds 为 0 时用默认 15 分钟。
	TTLSeconds int    `json:"ttl_seconds"`
	Note       string `json:"note"`
}

// EnrolTokenResponse 含明文令牌与可直接复制的安装命令。
//
// 「可复制的一行命令」是首启体验的核心：frp 完全没有 onboarding，
// 新用户必须读 README 并手写 TOML。
type EnrolTokenResponse struct {
	Token      string    `json:"token"`
	InstallCmd string    `json:"install_cmd"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// DefaultEnrolTTL 是入网令牌的默认有效期。
//
// 15 分钟：足够贴一条命令，短到丢了也不太要紧。
const DefaultEnrolTTL = 15 * time.Minute

func (s *Server) handleIssueEnrolToken(w http.ResponseWriter, r *http.Request, sess *session) {
	var req enrolTokenRequest
	// 允许空 body。
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)

	ttl := DefaultEnrolTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if s.snapshot == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "中继未就绪")
		return
	}
	token, cmd, err := s.snapshot.IssueEnrolToken(ttl, req.Note)
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindAgentEnrolled, Level: store.LevelInfo,
		Message: "签发入网令牌", Actor: sess.Username,
	})
	writeJSON(w, http.StatusOK, EnrolTokenResponse{
		Token: token, InstallCmd: cmd, ExpiresAt: time.Now().Add(ttl),
	})
}

type desktopPairingInviteRequest struct {
	// TTLSeconds 为 0 时使用默认 10 分钟。
	TTLSeconds int    `json:"ttl_seconds"`
	ListenPort uint16 `json:"listen_port"`
	Note       string `json:"note"`
}

const (
	defaultDesktopPairingInviteTTL = 10 * time.Minute
	maxDesktopPairingInviteTTL     = 24 * time.Hour
)

// handleCreateDesktopPairingInvite 创建一个只允许 Desktop bootstrap 的
// 一次性 bearer。管理员 session + CSRF/Origin 由 requireAuth 提供。
func (s *Server) handleCreateDesktopPairingInvite(
	w http.ResponseWriter, r *http.Request, sess *session,
) {
	issuer, ok := s.snapshot.(DesktopPairingInviteIssuer)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不支持 Desktop 配对")
		return
	}

	var req desktopPairingInviteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体解析失败")
		return
	}
	ttl := defaultDesktopPairingInviteTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl <= 0 || ttl > maxDesktopPairingInviteTTL {
		writeError(w, http.StatusBadRequest, "invalid",
			"ttl_seconds 必须在 1 秒到 24 小时之间")
		return
	}
	if req.ListenPort == 0 {
		writeError(w, http.StatusBadRequest, "invalid",
			"listen_port 必须是 1-65535")
		return
	}

	out, err := issuer.CreateDesktopPairingInvite(r.Context(), ttl, req.ListenPort, req.Note)
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindPairingInviteCreated, Level: store.LevelInfo,
		Message: "创建 Desktop 一次性配对邀请", Actor: sess.Username,
	})
	writeJSON(w, http.StatusOK, out)
}

// handleBootstrapDesktop 兑换一次性 Desktop invite。
//
// 这是一个窄权限、无管理员 session 的 endpoint：invite 不进入 query string，
// 不接受 backend/agent/tunnel 字段，也不走 CSRF。这样 Desktop 不需要知道
// Relay admin 凭据，同时 bearer 不能被改造成任意内网拨号。
func (s *Server) handleBootstrapDesktop(w http.ResponseWriter, r *http.Request) {
	bootstrapper, ok := s.snapshot.(DesktopBootstrapper)
	if !ok {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"本中继版本不支持 Desktop bootstrap")
		return
	}

	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		writeError(w, http.StatusUnauthorized, "missing_invite",
			"需要 Authorization: Bearer <一次性配对邀请>")
		return
	}

	// 当前协议没有请求字段；允许空 body，若有 body 则必须是空 JSON 对象，
	// 防止未来有人把 backend 等高风险字段悄悄加进来而被静默忽略。
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	var body map[string]json.RawMessage
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_request", "请求体解析失败")
		return
	}
	if len(body) != 0 {
		writeError(w, http.StatusBadRequest, "bad_request",
			"Desktop bootstrap 请求不接受任何字段")
		return
	}

	out, err := bootstrapper.BootstrapDesktop(r.Context(), parts[1])
	if err != nil {
		code, name := statusFor(err)
		writeError(w, code, name, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// fieldErrors 把 errors.Join 出来的多个校验错误拆成逐字段的结构。
//
// 这样前端能一次高亮所有坏字段，而不是让用户改一个、提交、再发现下一个。
func fieldErrors(err error) []FieldError {
	var out []FieldError
	var unwrap func(error)
	unwrap = func(e error) {
		if e == nil {
			return
		}
		// errors.Join 返回的类型实现了 Unwrap() []error。
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, sub := range joined.Unwrap() {
				unwrap(sub)
			}
			return
		}
		out = append(out, FieldError{Path: guessField(e), Message: e.Error()})
	}
	unwrap(err)
	if len(out) == 0 {
		out = []FieldError{{Message: err.Error()}}
	}
	return out
}

// guessField 从错误信息里推断它属于哪个字段。
//
// 这是一个启发式：真正的结构化字段路径需要校验器返回带路径的错误，
// 那是后续改进（见规格 §16）。当前的取舍是「让前端能大致定位」
// 好过「什么都不给」。
func guessField(err error) string {
	msg := err.Error()
	for field, keys := range map[string][]string{
		"slug":     {"slug"},
		"kind":     {"kind"},
		"tls":      {"tls"},
		"exposure": {"exposure"},
		"l4":       {"l4"},
		"router":   {"router"},
		"backend":  {"backend", "addr", "path"},
	} {
		for _, k := range keys {
			if containsFold(msg, k) {
				return field
			}
		}
	}
	return ""
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := range len(substr) {
			a, b := s[i+j], substr[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ── TURN ────────────────────────────────────────────────────────────────────

// handleTurnAllocations 列出当前 TURN 分配。
//
// pion/turn 没有枚举分配的 API，这份明细来自 internal/turnsrv 自己维护的表
// （靠 EventHandler 的生命周期回调 + 每分配一个的中继 socket 计量）。
func (s *Server) handleTurnAllocations(w http.ResponseWriter, r *http.Request, _ *session) {
	if s.turn == nil {
		// 如实说「没启用」，而不是回一个空列表。
		// 空列表会让用户以为「TURN 在跑但没人用」，从而去查客户端 ——
		// 方向完全错了。
		writeError(w, http.StatusServiceUnavailable, "turn_disabled",
			"本中继未启用 TURN（需要配置 -turn-public-ip）")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allocations": s.turn.Allocations()})
}

// turnCredentialRequest 是签发临时 TURN 凭据的请求体。
// MaxTurnCredentialTTL 是临时 TURN 凭据的有效期上限。
//
// # 为什么必须有上限
//
// TURN 临时凭据**无法吊销**：校验方只做 HMAC-SHA1(secret, username)，
// 而 username 里的时间戳就是它唯一的有效期。换 secret 会让所有在用的凭据
// 一起失效（包括正在通话的），所以那不是一条可用的应急手段。
//
// 而这些凭据会被塞进浏览器的 RTCPeerConnection 配置，对任何能看 devtools
// 的人都是明文。所以「短命」不是一个可选的加固，而是这套机制成立的前提。
//
// 24 小时的依据：足以覆盖一次长会议或一个工作日的连续使用，
// 而又短到「泄露了也只烂一天」。需要更长的场景应当去续签，不是延长有效期。
const MaxTurnCredentialTTL = 24 * time.Hour

type turnCredentialRequest struct {
	// UserID 会被嵌进凭据用户名，用于把分配归属到某个用户/租户。
	UserID string `json:"user_id"`
	// TTLSeconds 为 0 时用默认值。
	TTLSeconds int `json:"ttl_seconds"`
}

// handleMintTurnCredential 签发一对临时 TURN 凭据，并返回可直接喂给
// RTCPeerConnection 的 iceServers。
func (s *Server) handleMintTurnCredential(w http.ResponseWriter, r *http.Request, sess *session) {
	if s.turn == nil {
		writeError(w, http.StatusServiceUnavailable, "turn_disabled",
			"本中继未启用 TURN（需要配置 -turn-public-ip）")
		return
	}

	var req turnCredentialRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)

	ttl := time.Duration(req.TTLSeconds) * time.Second
	// TTL 必须有上限。
	//
	// # 为什么这不是「加固」
	//
	// TURN 临时凭据**无法吊销** —— 校验方只做 HMAC-SHA1(secret, username)，
	// 而 username 里的时间戳就是它唯一的有效期。换 secret 会让**所有**
	// 在用的凭据一起失效（包括正在通话的），所以那不是一条可用的应急手段。
	// 于是一张 ttl_seconds=3153600000 的凭据就是一张 100 年有效、
	// 谁都收不回来的中继通行证。
	//
	// 而临时凭据的整个设计前提就是「短命」：它会被塞进浏览器的
	// RTCPeerConnection 配置里，那个地方对任何能看 devtools 的人都是明文。
	if ttl > MaxTurnCredentialTTL {
		writeError(w, http.StatusBadRequest, "ttl_too_long",
			fmt.Sprintf("凭据有效期最长 %s（TURN 临时凭据无法吊销，"+
				"换密钥会让所有在用凭据一起失效，所以只能靠短有效期）",
				MaxTurnCredentialTTL))
		return
	}
	cfg, err := s.turn.MintCredential(req.UserID, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	// 签发凭据是一次授予访问权的动作，必须留痕。
	// 不记的话，「谁在什么时候拿走了一对能用 10 分钟的中继凭据」就无从追溯。
	_ = s.db.AppendEvent(r.Context(), store.Event{
		Kind: store.KindTurnCredential, Level: store.LevelInfo,
		Subject: req.UserID, Actor: sess.Username,
		Message: "签发了一对临时 TURN 凭据",
	})

	writeJSON(w, http.StatusOK, cfg)
}
