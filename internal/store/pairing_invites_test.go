package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

func pairingInviteSpec() PairingInviteSpec {
	return PairingInviteSpec{
		TenantID:       tunnel.DefaultTenantID,
		Scopes:         []string{"agent:enrol", "tunnel:create"},
		Backend:        tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:25808"},
		PublicHostname: "relay.example.test",
		PublicPort:     443,
		TLS:            tunnel.TLSGateway,
		TTL:            time.Hour,
		Note:           "test invite",
	}
}

func pairingRedeemRequest() PairingInviteRedeemRequest {
	spec := pairingInviteSpec()
	return PairingInviteRedeemRequest{
		TenantID: tunnel.DefaultTenantID,
		Scopes:   []string{"agent:enrol"},
		Backend:  spec.Backend,
		UsedBy:   "desktop-test",
	}
}

func TestPairingInviteRoundTripAndConstraints(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	plain, want, err := db.CreatePairingInvite(ctx, pairingInviteSpec())
	if err != nil {
		t.Fatalf("CreatePairingInvite: %v", err)
	}
	if plain == "" || want.ID == "" {
		t.Fatal("创建邀请应返回明文 token 与 ID")
	}

	got, err := db.getPairingInvite(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetPairingInvite: %v", err)
	}
	if got.TenantID != want.TenantID || got.PublicHostname != want.PublicHostname ||
		got.PublicPort != want.PublicPort || got.TLS != want.TLS ||
		got.Backend != want.Backend {
		t.Fatalf("邀请字段未保真：got=%+v want=%+v", got, want)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "agent:enrol" || got.Scopes[1] != "tunnel:create" {
		t.Fatalf("scopes 未规范化：%v", got.Scopes)
	}

	req := pairingRedeemRequest()
	redeemed, err := db.RedeemPairingInvite(ctx, plain, req)
	if err != nil {
		t.Fatalf("首次兑换: %v", err)
	}
	if redeemed.UsedBy != req.UsedBy || redeemed.UsedAt.IsZero() {
		t.Fatalf("兑换结果缺少消费信息：%+v", redeemed)
	}
}

func TestPairingInviteRejectsUsedAndExpired(t *testing.T) {
	t.Run("used", func(t *testing.T) {
		db := open(t)
		ctx := context.Background()
		plain, _, err := db.CreatePairingInvite(ctx, pairingInviteSpec())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.RedeemPairingInvite(ctx, plain, pairingRedeemRequest()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.RedeemPairingInvite(ctx, plain, pairingRedeemRequest()); !errors.Is(err, ErrPairingInviteUsed) {
			t.Fatalf("重复兑换应返回 ErrPairingInviteUsed，得到 %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		db := open(t)
		ctx := context.Background()
		plain, _, err := db.CreatePairingInvite(ctx, PairingInviteSpec{
			TenantID: tunnel.DefaultTenantID,
			Scopes:   []string{"agent:enrol"},
			Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:25808"},
			TLS:      tunnel.TLSPassthrough,
			TTL:      time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		orig := now
		now = func() int64 { return orig() + 10 }
		t.Cleanup(func() { now = orig })
		if _, err := db.RedeemPairingInvite(ctx, plain, pairingRedeemRequest()); !errors.Is(err, ErrPairingInviteExpired) {
			t.Fatalf("过期兑换应返回 ErrPairingInviteExpired，得到 %v", err)
		}
	})
}

func TestPairingInviteRejectsScopeTenantAndBackendEscalation(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	plain, _, err := db.CreatePairingInvite(ctx, pairingInviteSpec())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		req  PairingInviteRedeemRequest
		want error
	}{
		{
			name: "scope escalation",
			req: PairingInviteRedeemRequest{
				TenantID: tunnel.DefaultTenantID,
				Scopes:   []string{"agent:enrol", "admin"},
				Backend:  pairingInviteSpec().Backend,
			},
			want: ErrPairingInviteScopeDenied,
		},
		{
			name: "tenant mismatch",
			req: PairingInviteRedeemRequest{
				TenantID: "other",
				Scopes:   []string{"agent:enrol"},
				Backend:  pairingInviteSpec().Backend,
			},
			want: ErrPairingInviteTenantMismatch,
		},
		{
			name: "backend mismatch",
			req: PairingInviteRedeemRequest{
				TenantID: tunnel.DefaultTenantID,
				Scopes:   []string{"agent:enrol"},
				Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9999"},
			},
			want: ErrPairingInviteBackendMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.RedeemPairingInvite(ctx, plain, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("得到 %v，期望 %v", err, tc.want)
			}
			if got, err := db.getPairingInvite(ctx, mustPairingInviteID(t, db, plain)); err != nil {
				t.Fatal(err)
			} else if !got.UsedAt.IsZero() {
				t.Fatal("约束校验失败不应消费 invite")
			}
		})
	}
}

func TestPairingInviteConcurrentRedeemOnlyOneWins(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	plain, _, err := db.CreatePairingInvite(ctx, pairingInviteSpec())
	if err != nil {
		t.Fatal(err)
	}
	req := pairingRedeemRequest()

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.RedeemPairingInvite(ctx, plain, req)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var success, used int
	for err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrPairingInviteUsed):
			used++
		default:
			t.Errorf("并发兑换出现意外错误：%v", err)
		}
	}
	if success != 1 || used != callers-1 {
		t.Fatalf("并发兑换结果 success=%d used=%d，期望 1/%d", success, used, callers-1)
	}
}

func mustPairingInviteID(t *testing.T, db *DB, plain string) string {
	t.Helper()
	var id string
	if err := db.read.QueryRowContext(context.Background(),
		`SELECT id FROM pairing_invites WHERE token_hash = ?`, hashToken(plain)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
