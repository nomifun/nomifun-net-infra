#!/usr/bin/env sh
# 对 dist/SHA256SUMS 做 detached 签名。
#
# # 这个脚本只在**离线签名机**上跑
#
# 规格 §13.1：`make dist` 产出的 SHA256SUMS 是在**构建同一台机器**上生成的，
# 所以它只防传输损坏、不防构建机被攻陷。签名必须用一把**不在构建机上**的
# 长期密钥 —— 否则攻陷构建机的人可以同时改产物、改校验和、再签一次。
#
# 用法（在离线机上）：
#     NFR_SIGN_KEY=/path/to/ed25519-private.pem sh scripts/sign-release.sh dist
#
# 产出 dist/SHA256SUMS.sig（64 字节 raw Ed25519 签名）。
#
# # 为什么用 openssl Ed25519，而不是 minisign 或 cosign
#
# 规格说「minisign 或 cosign 的 --key 模式均可，定版前需实测确认工具可用性」。
# 实测结论：
#   * cosign 的 **keyless 模式在本仓不可用** —— 它依赖 CI 提供的 OIDC 身份，
#     而组织铁律禁用 GitHub Actions，没有那个身份来源。
#   * minisign 与 cosign 都需要**用户**先装一个额外的工具才能验签。
#     而 openssl 在几乎所有 Linux / macOS 上都已经在了 ——
#     一个「要先装工具才能验」的签名，多数用户会直接跳过验证，
#     那等于没有签名。
#
# Ed25519 而不是 RSA：签名 64 字节、公钥 32 字节，能直接贴进 README，
# 而 RSA 公钥长到只能放文件。
set -eu

DIST="${1:-dist}"
SUMS="$DIST/SHA256SUMS"
SIG="$SUMS.sig"

if [ -z "${NFR_SIGN_KEY:-}" ]; then
	echo "✗ 未设置 NFR_SIGN_KEY —— 它必须指向离线私钥（那把钥匙绝不该在构建机上）" >&2
	exit 1
fi
if [ ! -f "$NFR_SIGN_KEY" ]; then
	echo "✗ 私钥不存在：$NFR_SIGN_KEY" >&2
	exit 1
fi
if [ ! -f "$SUMS" ]; then
	echo "✗ 找不到 $SUMS —— 先在构建机上跑 make dist，再把 dist/ 拷到这台机器" >&2
	exit 1
fi

# **绝不**把私钥内容打印出来，连长度都不打 —— 那是一条侧信道。
openssl pkeyutl -sign -inkey "$NFR_SIGN_KEY" -rawin -in "$SUMS" -out "$SIG"

echo "✓ 已签名：$SIG（$(wc -c < "$SIG" | tr -d ' ') 字节）"
echo "  校验方用：sh scripts/verify-release.sh $DIST"
