package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/gateway"
)

// TestEveryGatewayAndDiscriminatorCounterReachesTheSnapshot 是一条**接线门禁**。
//
// # 为什么它必须存在
//
// 「加了计数器却没有读取点等于没加」这个错误本轮已经犯过三次：
// 网关的请求级 DeniedCIDR、判别器的 CarrierALPN、以及每隧道限额那四个 ——
// 每次都是递增了、而快照读的是另一个同名字段或压根不读。
//
// 症状很轻：没人报错、测试全绿，只是运维在排障时发现那个数字永远是 0。
// 而这类计数器存在的**唯一**理由就是排障时能看到。
//
// 所以这条测试用反射逐个比对两个结构体的字段：GatewayStats 与
// DiscriminatorStats 里的每一个 atomic 计数器，都必须在 SharedEntryStatus
// 里有一个落点。新增计数器却忘了接线时，它会红。
func TestEveryGatewayAndDiscriminatorCounterReachesTheSnapshot(t *testing.T) {
	// SharedEntryStatus 上的 int64 字段名集合（JSON 名与 Go 名都收）。
	got := map[string]bool{}
	st := reflect.TypeOf(console.SharedEntryStatus{})
	for i := range st.NumField() {
		f := st.Field(i)
		if f.Type.Kind() != reflect.Int64 {
			continue
		}
		got[strings.ToLower(f.Name)] = true
		if tag := f.Tag.Get("json"); tag != "" {
			got[strings.ToLower(strings.Split(tag, ",")[0])] = true
		}
	}

	// 计数器名 → 允许的落点名（同名或加前缀）。
	check := func(kind string, typ reflect.Type, prefixes []string) {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if f.Type.Name() != "Int64" { // atomic.Int64
				continue
			}
			name := strings.ToLower(f.Name)
			// 允许直接同名，或带上路径前缀（gateway_ / splice_ / tunnel_）。
			cands := []string{name}
			for _, p := range prefixes {
				cands = append(cands, p+name)
			}
			// snake_case 也认（GatewayDeniedCIDR ↔ gateway_denied_cidr）。
			var ok bool
			for _, c := range cands {
				if got[c] || got[strings.ReplaceAll(c, "_", "")] {
					ok = true
					break
				}
			}
			if !ok {
				// 再宽一格：把驼峰拆开逐段比对，覆盖 CarrierALPN ↔ carrier_alpn。
				snake := toSnake(f.Name)
				for _, p := range append([]string{""}, prefixes...) {
					if got[p+snake] {
						ok = true
						break
					}
				}
			}
			if !ok {
				t.Errorf("%s.%s 是一个计数器，但 SharedEntryStatus 里没有它的落点 —— "+
					"递增了却没有读取点等于没加（运维排障时它永远是 0）",
					kind, f.Name)
			}
		}
	}
	check("GatewayStats", reflect.TypeOf(gateway.GatewayStats{}), []string{"gateway_", "gateway"})
	check("DiscriminatorStats", reflect.TypeOf(gateway.DiscriminatorStats{}),
		[]string{"splice_", "splice", "tunnel_", "tunnel"})
}

// toSnake 把 CamelCase 转成 snake_case（连续大写当成一个词，覆盖 ALPN / CIDR / IP）。
func toSnake(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		upper := r >= 'A' && r <= 'Z'
		if upper && i > 0 {
			prevLower := rs[i-1] >= 'a' && rs[i-1] <= 'z'
			nextLower := i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z'
			if prevLower || nextLower {
				b.WriteByte('_')
			}
		}
		if upper {
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
