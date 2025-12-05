package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ConnectionPool manages reusable SSH connections.
// It caches connections by a key derived from connection parameters,
// allowing connection reuse across multiple resource operations.
type ConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*pooledConnection
	maxIdle     time.Duration
}

type pooledConnection struct {
	client   *Client
	lastUsed time.Time
	inUse    int // reference count
}

// NewConnectionPool creates a new connection pool.
// maxIdle specifies how long idle connections are kept before being closed.
func NewConnectionPool(maxIdle time.Duration) *ConnectionPool {
	pool := &ConnectionPool{
		connections: make(map[string]*pooledConnection),
		maxIdle:     maxIdle,
	}

	// Start background cleanup goroutine.
	go pool.cleanupLoop()

	return pool
}

// GetOrCreate gets an existing connection or creates a new one.
// The caller must call Release() when done with the connection.
func (p *ConnectionPool) GetOrCreate(config Config) (*Client, error) {
	key := p.connectionKey(config)

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for existing connection.
	if pc, ok := p.connections[key]; ok {
		// Verify connection is still valid.
		if pc.client != nil && pc.client.sshClient != nil {
			pc.inUse++
			pc.lastUsed = time.Now()
			return pc.client, nil
		}
		// Connection is stale, remove it.
		delete(p.connections, key)
	}

	// Create new connection.
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}

	p.connections[key] = &pooledConnection{
		client:   client,
		lastUsed: time.Now(),
		inUse:    1,
	}

	return client, nil
}

// Release returns a connection to the pool.
// The connection is not closed but may be reused by other callers.
func (p *ConnectionPool) Release(config Config) {
	key := p.connectionKey(config)

	p.mu.Lock()
	defer p.mu.Unlock()

	if pc, ok := p.connections[key]; ok {
		pc.inUse--
		if pc.inUse < 0 {
			pc.inUse = 0
		}
		pc.lastUsed = time.Now()
	}
}

// Close closes all connections in the pool.
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key, pc := range p.connections {
		if pc.client != nil {
			pc.client.Close()
		}
		delete(p.connections, key)
	}
}

// CloseIdle closes connections that have been idle for longer than maxIdle.
func (p *ConnectionPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, pc := range p.connections {
		if pc.inUse == 0 && now.Sub(pc.lastUsed) > p.maxIdle {
			if pc.client != nil {
				pc.client.Close()
			}
			delete(p.connections, key)
		}
	}
}

// connectionKey generates a unique key for a connection configuration.
func (p *ConnectionPool) connectionKey(config Config) string {
	// Create a key based on connection parameters.
	// We hash sensitive data to avoid storing credentials in the key.
	h := sha256.New()

	h.Write([]byte(config.Host))
	fmt.Fprintf(h, ":%d:", config.Port)
	h.Write([]byte(config.User))

	// Include auth method in key.
	if config.Password != "" {
		h.Write([]byte(":password:"))
		h.Write([]byte(config.Password))
	}
	if config.PrivateKey != "" {
		h.Write([]byte(":key:"))
		h.Write([]byte(config.PrivateKey))
	}
	if config.KeyPath != "" {
		h.Write([]byte(":keypath:"))
		h.Write([]byte(config.KeyPath))
	}

	// Include bastion info if present.
	if config.BastionHost != "" {
		h.Write([]byte(":bastion:"))
		h.Write([]byte(config.BastionHost))
		fmt.Fprintf(h, ":%d:", config.BastionPort)
	}

	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
}

// cleanupLoop periodically cleans up idle connections.
func (p *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(p.maxIdle / 2)
	defer ticker.Stop()

	for range ticker.C {
		p.CloseIdle()
	}
}

// Stats returns current pool statistics.
func (p *ConnectionPool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var inUse, idle int
	for _, pc := range p.connections {
		if pc.inUse > 0 {
			inUse++
		} else {
			idle++
		}
	}

	return PoolStats{
		Total: len(p.connections),
		InUse: inUse,
		Idle:  idle,
	}
}

// PoolStats contains pool statistics.
type PoolStats struct {
	Total int
	InUse int
	Idle  int
}

// DefaultPool is the default connection pool for the provider.
// It keeps idle connections for 5 minutes.
var DefaultPool = NewConnectionPool(5 * time.Minute)

// GetConnection gets or creates a connection from the default pool.
func GetConnection(config Config) (*Client, error) {
	return DefaultPool.GetOrCreate(config)
}

// ReleaseConnection releases a connection back to the default pool.
func ReleaseConnection(config Config) {
	DefaultPool.Release(config)
}

// CloseAllConnections closes all connections in the default pool.
func CloseAllConnections() {
	DefaultPool.Close()
}
