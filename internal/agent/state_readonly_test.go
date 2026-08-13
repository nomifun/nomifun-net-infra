package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveFailsLoudlyWhenTheDirectoryTurnsReadOnlyLater 造出「落盘会失败」这个处境。
//
// OpenStore 在启动时已经用「建一个临时文件再删掉」证明过目录可写，所以落盘失败
// 只可能是**启动之后**才出现的状况：盘满、挂载被改成只读、权限被别的东西改掉。
//
// 这条测试的价值不在于断言错误文案，而在于**证明那条失败路径是可达的** ——
// cmd/nfagent 那边的处理逻辑（不退出、置脏标记、每次重连重试、周期性提醒）
// 全部挂在这个返回值上，而如果这条路径根本走不到，那些代码就是无人验证的。
func TestSaveFailsLoudlyWhenTheDirectoryTurnsReadOnlyLater(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时只读目录照样可写")
	}
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	// 先正常落一次，确认前置成立。
	if err := s.Save(Credential{AgentID: "a", Key: "00ff"}); err != nil {
		t.Fatalf("前置不成立，正常落盘就失败了：%v", err)
	}

	// 现在把目录改成只读 —— 模拟「启动之后盘变了」。
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := s.Save(Credential{AgentID: "b", Key: "11ee"}); err == nil {
		t.Fatal("只读目录下落盘应当报错 —— 若它静默成功，" +
			"cmd/nfagent 那套「不退出但持续抱怨」的处理就永远走不到")
	}

	// 而且不能留下临时文件（失败路径也要清理干净）。
	_ = os.Chmod(dir, 0o700)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("失败路径留下了临时文件 %s", e.Name())
		}
	}
}
