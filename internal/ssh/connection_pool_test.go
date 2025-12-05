package ssh

import (
	"testing"
	"time"
)

func TestConnectionPool_ConnectionKey(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	tests := []struct {
		name    string
		config1 Config
		config2 Config
		same    bool
	}{
		{
			name: "same config same key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			same: true,
		},
		{
			name: "different host different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.101",
				Port: 22,
				User: "root",
			},
			same: false,
		},
		{
			name: "different port different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 2222,
				User: "root",
			},
			same: false,
		},
		{
			name: "different user different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "deploy",
			},
			same: false,
		},
		{
			name: "different auth different key",
			config1: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret1",
			},
			config2: Config{
				Host:     "192.168.1.100",
				Port:     22,
				User:     "root",
				Password: "secret2",
			},
			same: false,
		},
		{
			name: "with bastion different key",
			config1: Config{
				Host: "192.168.1.100",
				Port: 22,
				User: "root",
			},
			config2: Config{
				Host:        "192.168.1.100",
				Port:        22,
				User:        "root",
				BastionHost: "bastion.example.com",
			},
			same: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := pool.connectionKey(tt.config1)
			key2 := pool.connectionKey(tt.config2)

			if tt.same && key1 != key2 {
				t.Errorf("expected same key, got %s and %s", key1, key2)
			}
			if !tt.same && key1 == key2 {
				t.Errorf("expected different keys, got same: %s", key1)
			}
		})
	}
}

func TestConnectionPool_Stats(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("expected 0 total connections, got %d", stats.Total)
	}
	if stats.InUse != 0 {
		t.Errorf("expected 0 in-use connections, got %d", stats.InUse)
	}
	if stats.Idle != 0 {
		t.Errorf("expected 0 idle connections, got %d", stats.Idle)
	}
}

func TestConnectionPool_Release(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	defer pool.Close()

	config := Config{
		Host: "192.168.1.100",
		Port: 22,
		User: "root",
	}

	// Release without getting should not panic.
	pool.Release(config)

	// Release multiple times should not panic.
	pool.Release(config)
	pool.Release(config)
}

func TestConnectionPool_Close(t *testing.T) {
	pool := NewConnectionPool(time.Minute)

	// Close should work on empty pool.
	pool.Close()

	// Verify pool is empty.
	stats := pool.Stats()
	if stats.Total != 0 {
		t.Errorf("expected 0 connections after close, got %d", stats.Total)
	}
}

func TestConnectionPool_CloseIdle(t *testing.T) {
	pool := NewConnectionPool(time.Millisecond * 10)
	defer pool.Close()

	// CloseIdle on empty pool should not panic.
	pool.CloseIdle()
}

func TestNewConnectionPool(t *testing.T) {
	pool := NewConnectionPool(time.Minute)
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	pool.Close()
}

func TestDefaultPool(t *testing.T) {
	if DefaultPool == nil {
		t.Fatal("expected DefaultPool to be initialized")
	}

	stats := DefaultPool.Stats()
	// Just verify it works.
	_ = stats
}

func TestPoolStats(t *testing.T) {
	stats := PoolStats{
		Total: 10,
		InUse: 5,
		Idle:  5,
	}

	if stats.Total != 10 {
		t.Errorf("Total = %d, want 10", stats.Total)
	}
	if stats.InUse != 5 {
		t.Errorf("InUse = %d, want 5", stats.InUse)
	}
	if stats.Idle != 5 {
		t.Errorf("Idle = %d, want 5", stats.Idle)
	}
}
