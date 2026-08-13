#!/usr/bin/env sh
# 一键安装 nfrelay / nfagent。
#
# # 它在执行任何东西**之前**验签
#
# 规格 §13.1 的硬要求。一个「先下载再执行、顺便校验一下」的安装脚本等于没有
# 校验：等你算出校验和不对的时候，那个二进制已经跑过了。
#
# 所以顺序是：下载 → 验签 → 核校验和 → **才**安装。任何一步失败即中止，
# 且**不留下**已下载的文件（半个失败的安装比明确的失败更难排查）。
#
# 用法：
#     sh install.sh <发布目录或 URL 前缀> [nfrelay|nfagent]
#
# 本地目录的例子（离线安装）：
#     sh scripts/install.sh ./dist nfagent
set -eu

SRC="${1:-}"
WHAT="${2:-nfagent}"
PUB="${NFR_PUBKEY:-release/nomirelay-release.pub}"
DEST="${NFR_PREFIX:-/usr/local/bin}"

fail() { echo "✗ $1" >&2; exit 1; }

[ -n "$SRC" ] || fail "用法：sh install.sh <发布目录或 URL 前缀> [nfrelay|nfagent]"
case "$WHAT" in
nfrelay | nfagent) ;;
*) fail "只能安装 nfrelay 或 nfagent，收到 $WHAT" ;;
esac

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
armv7* | armv6*) arch=arm ;;
i386 | i686) arch=386 ;;
riscv64) arch=riscv64 ;;
mips) arch=mips ;;
mipsel) arch=mipsle ;;
*) fail "不认识的架构 $arch —— 请手工挑一个产物并用 verify-release.sh 自己验签" ;;
esac
bin="$WHAT-$os-$arch"

work=$(mktemp -d)
# **失败也要清干净**：半个失败的安装比明确的失败更难排查。
trap 'rm -rf "$work"' EXIT INT TERM

fetch() {
	# $1 = 相对名，$2 = 落地路径
	case "$SRC" in
	http://* | https://*)
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL "$SRC/$1" -o "$2" || return 1
		elif command -v wget >/dev/null 2>&1; then
			wget -qO "$2" "$SRC/$1" || return 1
		else
			fail "既没有 curl 也没有 wget"
		fi
		;;
	*)
		[ -f "$SRC/$1" ] || return 1
		cp "$SRC/$1" "$2" || return 1
		;;
	esac
}

echo "→ 取 SHA256SUMS 与签名"
fetch SHA256SUMS "$work/SHA256SUMS" || fail "取不到 SHA256SUMS"
fetch SHA256SUMS.sig "$work/SHA256SUMS.sig" ||
	fail "取不到签名 —— **未签名的发布不要装**（校验和只防损坏，不防篡改）"

echo "→ 验签（在下载二进制之前）"
[ -f "$PUB" ] || fail "找不到公钥 $PUB。设 NFR_PUBKEY 指向它，或从仓库取。"
command -v openssl >/dev/null 2>&1 || fail "需要 openssl 来验签"
openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin \
	-in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1 ||
	fail "签名校验失败 —— 这份清单不是用我们的密钥签的。**立刻停止。**"
echo "  ✓ 签名有效"

echo "→ 取 $bin"
fetch "$bin" "$work/$bin" || fail "这份发布里没有 $bin"

echo "→ 核对校验和"
# 只核这一个文件：清单里有全部平台，我们只下载了一个。
want=$(grep "  $bin\$" "$work/SHA256SUMS" | awk '{print $1}')
[ -n "$want" ] || fail "$bin 不在已签名的清单里 —— 清单外的文件没有签名覆盖，不要执行"
got=$(sha256sum "$work/$bin" | awk '{print $1}')
[ "$want" = "$got" ] || fail "校验和不符：期望 $want，实际 $got"
echo "  ✓ $bin 校验和匹配"

echo "→ 安装到 $DEST"
chmod +x "$work/$bin"
if [ -w "$DEST" ]; then
	mv "$work/$bin" "$DEST/$WHAT"
else
	command -v sudo >/dev/null 2>&1 || fail "$DEST 不可写，且没有 sudo"
	sudo mv "$work/$bin" "$DEST/$WHAT"
	sudo chmod +x "$DEST/$WHAT"
fi
echo "✓ 已安装 $DEST/$WHAT"
"$DEST/$WHAT" -version || true
