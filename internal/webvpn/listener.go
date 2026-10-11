package webvpn

import (
	"net"
	"sync"
)

// LimitedListener bounds active connections, including incomplete TLS handshakes.
type LimitedListener struct {
	net.Listener
	mu    sync.Mutex
	peers map[string]int
	total int
}

func Limit(l net.Listener) *LimitedListener {
	return &LimitedListener{Listener: l, peers: map[string]int{}}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *LimitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		l.mu.Lock()
		if l.total >= 1024 || l.peers[ip] >= 32 {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.total++
		l.peers[ip]++
		l.mu.Unlock()
		return &limitedConn{Conn: c, release: func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			l.peers[ip]--
			if l.peers[ip] == 0 {
				delete(l.peers, ip)
			}
		}}, nil
	}
}
