package carrier

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// CertPool 抽象根证书池，便于测试注入。
type CertPool interface {
	Pool() *x509.CertPool
}

// SystemCertPool 用系统根证书池。
type SystemCertPool struct{}

// Pool 返回 nil，让 crypto/tls 使用系统默认池。
func (SystemCertPool) Pool() *x509.CertPool { return nil }

// StaticCertPool 包装一个显式构造的池。
type StaticCertPool struct{ P *x509.CertPool }

// Pool 返回被包装的池。
func (s StaticCertPool) Pool() *x509.CertPool { return s.P }

// SPKIPin 计算一份证书的 SPKI SHA-256 指纹。
//
// 钉公钥（SubjectPublicKeyInfo）而不是钉整张证书，是因为证书轮换时
// 只要沿用同一密钥对，指纹就不变 —— 否则每次续期都要重新分发指纹，
// 运维上必然被绕过。
func SPKIPin(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// SPKIPinBase64 返回指纹的 base64 形式，用于控制台展示与配置文件。
func SPKIPinBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(SPKIPin(cert))
}

// ParseSPKIPin 解析 base64 形式的指纹。
func ParseSPKIPin(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("carrier: SPKI 指纹不是合法 base64：%w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("carrier: SPKI 指纹长度为 %d 字节，期望 %d", len(raw), sha256.Size)
	}
	return raw, nil
}

// ErrPinMismatch 表示服务端证书的 SPKI 指纹与预期不符。
var ErrPinMismatch = errors.New("carrier: 服务端证书 SPKI 指纹不匹配（可能存在中间人）")

// pinVerifier 返回一个校验 SPKI 指纹的 VerifyPeerCertificate 回调。
//
// 之所以要自己解析 rawCerts 而不用 verifiedChains：调用方已经把
// InsecureSkipVerify 设为 true，所以 verifiedChains 是空的。
func pinVerifier(want []byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("carrier: 服务端未提供任何证书")
		}
		// 只信叶子证书（rawCerts[0]）。若比对整条链上的任一证书，
		// 一个持有中间 CA 的攻击者就能签出任意叶子证书通过校验。
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("carrier: 解析服务端证书失败：%w", err)
		}
		got := SPKIPin(leaf)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fmt.Errorf("%w：期望 %s，实际 %s",
				ErrPinMismatch,
				base64.StdEncoding.EncodeToString(want),
				base64.StdEncoding.EncodeToString(got))
		}
		return nil
	}
}
