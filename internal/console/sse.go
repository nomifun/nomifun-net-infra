package console

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Event 是一条推给控制台的实时事件。
type Event struct {
	// Type 对应 SSE 的 event: 字段，前端按它分派。
	//
	// hello   连接建立时的快照 + 服务器时间
	// metric  周期性指标（1Hz）
	// session 会话增删
	// state   隧道/agent 状态变化
	// log     限流后的日志行
	// health  流健康（丢帧数）
	Type string `json:"-"`
	Data any    `json:"data"`
}

// SSE 事件类型。
const (
	EventHello   = "hello"
	EventMetric  = "metric"
	EventSession = "session"
	EventState   = "state"
	EventLog     = "log"
	// EventHealth 携带流健康信息（丢帧数、订阅者数、服务器时间）。
	//
	// 必须是一个真实事件帧而不是 SSE 注释：EventSource 按规范看不见注释行。
	EventHealth = "health"
)

// eventHub 把事件广播给所有订阅者。
//
// # 为什么是一个 SSE 端点按 topic 多路复用，而不是每个图表一条流
//
// HTTP/1.1 下浏览器每源约 6 连接上限，一个图表一个 EventSource 会把仪表盘
// 拖死。控制台监听器启用 HTTP/2 之后限制放宽，但多路复用仍是对的：
// 一条流、按 event: 字段分派，客户端代码也更简单。
//
// # 为什么是采样而非排队
//
// 慢客户端（比如一个后台标签页）不能拖慢中继。订阅者的 channel 满了就
// **丢弃**该帧并累加计数器，界面上显示为「流健康」指示点。
// 这与数据面是同一条法则：实时路径永不阻塞。
// frp 的下行 UDP 队列满时会阻塞（server/proxy/udp.go:140），
// 那个错误在这里绝不重复。
type eventHub struct {
	mu     sync.RWMutex
	subs   map[uint64]*subscriber
	nextID uint64

	log *slog.Logger

	// dropped 是全局丢弃计数，通过 hello 帧告知前端。
	dropped atomic.Int64
}

type subscriber struct {
	ch chan sseFrame
	// dropped 是这个订阅者自己的丢弃数，前端用它显示流健康。
	dropped atomic.Int64
}

// sseFrame 是一条已序列化的 SSE 帧。
//
// 提前序列化一次而不是每个订阅者各序列化一遍：广播是 1:N，
// 序列化成本不该乘以 N。
type sseFrame struct {
	id    int64
	event string
	data  []byte
}

// subscriberQueueDepth 是每个订阅者的缓冲深度。
//
// 32 帧 ≈ 1Hz 指标下 32 秒的积压容量。再深没有意义：
// 一个落后 32 秒的控制台看到的已经是历史，不如丢掉旧帧显示最新状态。
const subscriberQueueDepth = 32

func newEventHub(log *slog.Logger) *eventHub {
	if log == nil {
		log = slog.Default()
	}
	return &eventHub{subs: make(map[uint64]*subscriber), log: log}
}

var eventSeq atomic.Int64

// publish 广播一条事件。**绝不阻塞**。
func (h *eventHub) publish(e Event) {
	if e.Type == "" {
		e.Type = EventState
	}
	payload, err := json.Marshal(e.Data)
	if err != nil {
		h.log.Warn("序列化事件失败", "type", e.Type, "err", err)
		return
	}
	frame := sseFrame{id: eventSeq.Add(1), event: e.Type, data: payload}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, sub := range h.subs {
		select {
		case sub.ch <- frame:
		default:
			// 满了就丢。计数让它可见 —— 静默丢弃才是真正的问题。
			sub.dropped.Add(1)
			h.dropped.Add(1)
		}
	}
}

// Publish 是给中继核心用的导出入口。
func (h *eventHub) Publish(eventType string, data any) {
	h.publish(Event{Type: eventType, Data: data})
}

// PublishSession 推一帧会话开/关，并报告**有没有订阅者收到**。
//
// # 为什么这一帧需要一个返回值，而别的不需要
//
// 会话帧的速率由**外部输入**（用户连接）决定，所以它是**可牺牲的**。
// 而调用方需要知道开启帧有没有真的发出去 ——
// 只发了 close 而没发过 open 会在界面上留下一条永不消失的幽灵行。
//
// 返回 false 的两种情况都算「没发出去」：没有订阅者（没人看控制台，
// 那时推送毫无意义），或者所有订阅者的队列都满了。
func (s *Server) PublishSession(f SessionFrame) bool {
	return s.hub.publishSession(f)
}

// publishSession 与 publish 同形，只是回报「至少一个订阅者收到了吗」。
func (h *eventHub) publishSession(f SessionFrame) bool {
	payload, err := json.Marshal(f)
	if err != nil {
		h.log.Warn("序列化会话帧失败", "err", err)
		return false
	}
	frame := sseFrame{id: eventSeq.Add(1), event: EventSession, data: payload}

	h.mu.RLock()
	defer h.mu.RUnlock()
	delivered := false
	for _, sub := range h.subs {
		select {
		case sub.ch <- frame:
			delivered = true
		default:
			sub.dropped.Add(1)
			h.dropped.Add(1)
		}
	}
	return delivered
}

func (h *eventHub) subscribe() (uint64, *subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	sub := &subscriber{ch: make(chan sseFrame, subscriberQueueDepth)}
	h.subs[h.nextID] = sub
	return h.nextID, sub
}

func (h *eventHub) unsubscribe(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, id)
}

// Subscribers 返回当前订阅者数，供指标使用。
func (h *eventHub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// heartbeatInterval 是 SSE 注释心跳间隔。
//
// 中间盒与反向代理常在 30–60 秒无数据后掐掉连接。15 秒发一个注释行
// （`:` 开头，客户端会忽略）让连接保持活跃，且不污染事件流。
const heartbeatInterval = 15 * time.Second

// heartbeatIntervalForTest 让测试能把心跳调快，否则要等满 15 秒。
var heartbeatIntervalForTest = heartbeatInterval

// handleEventStream 是 SSE 端点。
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request, _ *session) {
	// ResponseController 是 Go 1.20+ 的正规做法，取代对 http.Flusher 的类型断言。
	rc := http.NewResponseController(w)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// 明确关掉 nginx 之类的缓冲，否则事件会被攒着一起发，实时性全失。
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	id, sub := s.hub.subscribe()
	defer s.hub.unsubscribe(id)

	// hello 帧：带上快照与服务器时间。
	//
	// 服务器时间让前端能算出自己的时钟偏移；这在排查「为什么图表时间轴不对」
	// 时是第一个要看的东西。
	hello := map[string]any{
		"server_time": time.Now().UnixMilli(),
		"seq":         eventSeq.Load(),
		// 接口契约版本。
		//
		// 前端拿它与自己编译进去的版本比对，不一致就横幅提示刷新
		//（stream.ts 的 onHello → AppLayout 的 ContractBanner）。
		//
		// **不发它 = 那条提示永远不会出现。** 前端的判据是
		// `f.api_contract_version !== undefined && ... !== __API_CONTRACT_VERSION__`，
		// 服务端不发的话第一个条件就不成立 —— 整条机制（算了、有类型、
		// 有横幅）在生产里是死的，而它要覆盖的正是「中继升级了、浏览器还挂着
		// 旧前端」那段时间：界面看起来正常但数字不完整，
		// 而后端宽容、前端类型也宽容，没有任何一层会报错。
		"api_contract_version": APIContractVersion,
	}
	if s.snapshot != nil {
		hello["snapshot"] = s.snapshot.Snapshot()
	}
	if err := writeSSE(w, rc, sseFrame{
		id: eventSeq.Add(1), event: EventHello, data: mustJSON(hello),
	}); err != nil {
		return
	}

	ticker := time.NewTicker(heartbeatIntervalForTest)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case frame := <-sub.ch:
			if err := writeSSE(w, rc, frame); err != nil {
				return
			}

		case <-ticker.C:
			// 心跳分两部分。
			//
			// 1) 一个 SSE 注释行保持连接活跃。中间盒与反向代理常在
			//    30–60 秒无数据后掐掉连接，注释行（`:` 开头）能防住这一点
			//    且不污染事件流。
			// 2) 一个**真实的 health 事件帧**携带丢帧数。
			//
			// 丢帧数不能放在注释里：`EventSource` 按规范**看不见注释行**，
			// 前端拿不到它，那个「流健康点」就成了恒为 0 的死指标。
			// 这是控制台前端在联调时报出来的 —— 我原本只写了注释行。
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := writeSSE(w, rc, sseFrame{
				id:    eventSeq.Add(1),
				event: EventHealth,
				data: mustJSON(map[string]any{
					"dropped":     sub.dropped.Load(),
					"subscribers": s.hub.Subscribers(),
					"server_time": time.Now().UnixMilli(),
				}),
			}); err != nil {
				return
			}
		}
	}
}

// writeSSE 写一条 SSE 帧并立刻 flush。
//
// 每帧都要 Flush：不 flush 的话数据会留在 bufio 里等缓冲满，
// 而 1Hz 的小帧可能几分钟才填满一个缓冲 —— 那就完全不是实时了。
func writeSSE(w http.ResponseWriter, rc *http.ResponseController, f sseFrame) error {
	// id 让客户端断线重连时能带 Last-Event-ID 续传。
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: ", f.id, f.event); err != nil {
		return err
	}
	if _, err := w.Write(f.data); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return err
	}
	return rc.Flush()
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"序列化失败"}`)
	}
	return b
}

// StartMetricsPump 启动一个 1Hz 的指标推送循环。
//
// 由中继在启动时调用。返回的函数用于停止它。
func (s *Server) StartMetricsPump(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = time.Second
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 没有订阅者时不做任何工作 —— 一个没人看的仪表盘
				// 不该消耗中继的 CPU。
				if s.hub.Subscribers() == 0 || s.snapshot == nil {
					continue
				}
				s.hub.publish(Event{Type: EventMetric, Data: s.snapshot.Snapshot()})
			}
		}
	}()
	return func() { close(done) }
}

// lastEventID 解析 Last-Event-ID 头。
//
// v1 不实现真正的续传（那需要一个环形缓冲保留最近事件），
// 但把这个头解析出来并记录，是为了让「客户端确实在用它」这件事可观测 ——
// 等真要做续传时不必先加埋点。
func lastEventID(r *http.Request) int64 {
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

var _ = lastEventID
