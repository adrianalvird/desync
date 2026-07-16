//pkg/session/pool.go

package session

import (
	"crypto/tls"
	"net"
)

type connPool struct {
	host   string
	scheme string
	pool   chan net.Conn
}

func newConnPool(host, scheme string, size int) *connPool {
	return &connPool{
		host:   host,
		scheme: scheme,
		pool:   make(chan net.Conn, size),
	}
}

func (p *connPool) Get() (net.Conn, error) {
	select {
	case conn := <-p.pool:
		return conn, nil
	default:
		return p.newConn()
	}
}

func (p *connPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}
	select {
	case p.pool <- conn:
	default:
		conn.Close()
	}
}

func (p *connPool) newConn() (net.Conn, error) {
	hostPort := p.host
	if p.scheme == "https" {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		return tls.Dial("tcp", hostPort, conf)
	}
	return net.Dial("tcp", hostPort)
}

func (p *connPool) Close() {
	close(p.pool)
	for conn := range p.pool {
		conn.Close()
	}
}