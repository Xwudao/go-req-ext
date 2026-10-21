// Package persist provides small, standard-library-only byte stores for
// go-req extensions such as the jar package.
//
// A Store is intentionally opaque: packages layer their own encoding (JSON,
// gob, or anything else) on top of Load and Save. Memory and File are the
// built-in implementations.
package persist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNotExist is returned by Store.Load when nothing has been persisted yet.
// Implementations may wrap it; callers should use errors.Is.
var ErrNotExist = errors.New("persist: value does not exist")

// Store persists an opaque byte slice.
//
// Implementations must be safe for concurrent use. Save replaces the previous
// value atomically from a reader's perspective. Load returns ErrNotExist when
// no value has been saved.
type Store interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, data []byte) error
	Delete(ctx context.Context) error
}

// StoreFunc adapts functions to a Store. A nil function returns an error when
// called; it never panics.
type StoreFunc struct {
	LoadFunc   func(ctx context.Context) ([]byte, error)
	SaveFunc   func(ctx context.Context, data []byte) error
	DeleteFunc func(ctx context.Context) error
}

// Load implements Store.
func (s StoreFunc) Load(ctx context.Context) ([]byte, error) {
	if s.LoadFunc == nil {
		return nil, errors.New("persist: StoreFunc.LoadFunc is nil")
	}
	return s.LoadFunc(ctx)
}

// Save implements Store.
func (s StoreFunc) Save(ctx context.Context, data []byte) error {
	if s.SaveFunc == nil {
		return errors.New("persist: StoreFunc.SaveFunc is nil")
	}
	return s.SaveFunc(ctx, data)
}

// Delete implements Store.
func (s StoreFunc) Delete(ctx context.Context) error {
	if s.DeleteFunc == nil {
		return errors.New("persist: StoreFunc.DeleteFunc is nil")
	}
	return s.DeleteFunc(ctx)
}

// LoadJSON loads data from store and decodes it into v.
//
// ErrNotExist is returned unchanged so callers can distinguish a missing value
// from an invalid one.
func LoadJSON(ctx context.Context, store Store, v any) error {
	if store == nil {
		return errors.New("persist: nil store")
	}
	data, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("persist: decode JSON: %w", err)
	}
	return nil
}

// SaveJSON encodes v as JSON and saves it to store.
func SaveJSON(ctx context.Context, store Store, v any) error {
	if store == nil {
		return errors.New("persist: nil store")
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("persist: encode JSON: %w", err)
	}
	return store.Save(ctx, data)
}
