package store

import (
	"crypto/sha256"
	"encoding/hex"
)

// EnrolAgentID 返回一个入网令牌兑换后将使用的 agent ID。
//
// 入网令牌本身只在兑换前短暂存在；把 ID 作为哈希前缀派生出来，
// 让控制面可以在 agent 真正上线前安全地预绑定隧道，而不需要
// 读取或保存明文凭据。
func EnrolAgentID(plainToken string) string {
	sum := sha256.Sum256([]byte(plainToken))
	return "agent-" + hex.EncodeToString(sum[:])[:12]
}
