package mockedge

import (
	"net"
	"strings"
	"sync"
)

// VHostFeedMock is the reverse proxy redirect feed: a TCP server that, on each connection,
// writes the current newline-delimited hostname set and closes (so the reader sees
// EOF). The served set is swappable to drive vhost-change tests.
type VHostFeedMock struct {
	ln   net.Listener
	mu   sync.Mutex
	body string
	done chan struct{}
}

// NewVHostFeed starts the feed server on 127.0.0.1:0.
func NewVHostFeed(lines ...string) (*VHostFeedMock, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &VHostFeedMock{ln: ln, body: join(lines), done: make(chan struct{})}
	go f.serve()
	return f, nil
}

// Addr is the host:port to set as the vhost feed source.
func (f *VHostFeedMock) Addr() string { return f.ln.Addr().String() }

// Set replaces the served hostname set (effective on the next fetch).
func (f *VHostFeedMock) Set(lines ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = join(lines)
}

// Close stops the server.
func (f *VHostFeedMock) Close() error {
	close(f.done)
	return f.ln.Close()
}

func (f *VHostFeedMock) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
				return
			}
		}
		f.mu.Lock()
		body := f.body
		f.mu.Unlock()
		_, _ = conn.Write([]byte(body))
		conn.Close()
	}
}

func join(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
