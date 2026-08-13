#!/usr/bin/env sh
# 校验一份发布产物：先验签名，再核对每个文件的 SHA256。
#
# # 顺序不能反
#
# 先验签名再核校验和：反过来的话，一个被替换了产物**并且**改了 SHA256SUMS
# 的发布会先通过校验和这一步 —— 而那正是签名要挡的攻击。
# 校验和只回答「文件与清单一致吗」，签名回答「这份清单是我们发的吗」。
#
# 用法：
#     sh scripts/verify-release.sh dist [公钥路径]
#
# 公钥默认取 release/nomirelay-release.pub（随仓库分发）。
set -eu

DIST="${1:-dist}"
PUB="${2:-release/nomirelay-release.pub}"
SUMS="$DIST/SHA256SUMS"
SIG="$SUMS.sig"

fail() { echo "✗ $1" >&2; exit 1; }

[ -f "$PUB" ] || fail "找不到公钥：$PUB"
[ -f "$SUMS" ] || fail "找不到 $SUMS"
[ -f "$SIG" ] || fail "找不到签名 $SIG —— 未签名的发布**不要用**（校验和只防损坏，不防篡改）"

# ── 第一步：签名 ──
if ! openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin -in "$SUMS" -sigfile "$SIG" >/dev/null 2>&1; then
	fail "签名校验失败 —— 这份 SHA256SUMS 不是用我们的密钥签的。**立刻停止安装。**"
fi
echo "✓ 签名有效（Ed25519，公钥 $PUB）"

# ── 第二步：校验和 ──
#
# 在 DIST 目录里跑：SHA256SUMS 里的路径是相对的。
# 只核对清单里**存在的**文件；多出来的文件单独报告 ——
# 一个不在清单里的可执行文件是一个该被看见的信号。
( cd "$DIST" && sha256sum -c SHA256SUMS --quiet ) || fail "校验和不符 —— 产物与清单不一致"
echo "✓ 校验和全部匹配"

extra=""
for f in "$DIST"/*; do
	name=$(basename "$f")
	case "$name" in
	SHA256SUMS | SHA256SUMS.sig) continue ;;
	esac
	if ! grep -q "  $name\$" "$SUMS" 2>/dev/null; then
		extra="$extra $name"
	fi
done
if [ -n "$extra" ]; then
	echo "⚠ 这些文件不在清单里：$extra"
	echo "  清单外的文件没有被签名覆盖 —— 不要执行它们。"
fi
echo "✓ 这份发布可以使用"
