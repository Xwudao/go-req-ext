package persist

import (
	"context"
	"sync"
)

// Memory is an in-memory Store. It is useful for tests and for sharing state
// inside one process.
//
// The zero value is ready to use.
type Memory struct {
	mu     sync.RWMutex
	data   []byte
	exists bool
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{}
}

// Load implements Store.
func (m *Memory) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.exists {
		return nil, ErrNotExist
	}
	return append([]byte(nil), m.data...), nil
}

// Save implements Store.
func (m *Memory) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	m.data = append([]byte(nil), data...)
	m.exists = true
	m.mu.Unlock()
	return nil
}

// Delete implements Store.
func (m *Memory) Delete(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	m.data = nil
	m.exists = false
	m.mu.Unlock()
	return nil
}
