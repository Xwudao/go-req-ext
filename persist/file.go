package persist

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// File is a Store backed by a single file.
//
// Save writes to a temporary file in the same directory and renames it into
// place, so readers never observe a partially written value. The default file
// mode is 0600 and the default directory mode is 0700.
type File struct {
	path    string
	perm    fs.FileMode
	dirPerm fs.FileMode

	mu sync.RWMutex
}

// FileOption configures a File store.
type FileOption func(*File)

// WithFileMode sets the permissions used when creating the data file.
func WithFileMode(mode fs.FileMode) FileOption {
	return func(f *File) {
		f.perm = mode
	}
}

// WithDirMode sets the permissions used when creating missing parent
// directories.
func WithDirMode(mode fs.FileMode) FileOption {
	return func(f *File) {
		f.dirPerm = mode
	}
}

// NewFile returns a file store rooted at path. The file is created lazily by
// Save; NewFile performs no I/O.
func NewFile(path string, opts ...FileOption) *File {
	f := &File{
		path:    path,
		perm:    0o600,
		dirPerm: 0o700,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(f)
		}
	}
	return f
}

// Path returns the backing file path.
func (f *File) Path() string {
	return f.path
}

// Load implements Store.
func (f *File) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.path == "" {
		return nil, errors.New("persist: empty file path")
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("persist: read %s: %w", f.path, err)
	}
	return data, nil
}

// Save implements Store.
func (f *File) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.path == "" {
		return errors.New("persist: empty file path")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, f.dirPerm); err != nil {
		return fmt.Errorf("persist: create directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("persist: create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(f.perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persist: set file mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persist: write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("persist: sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("persist: close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		return fmt.Errorf("persist: replace %s: %w", f.path, err)
	}
	cleanup = false

	// Syncing the directory makes the rename durable on filesystems that
	// require it. Failure here is not fatal: the data itself is already safe.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Delete implements Store. Deleting a missing file is not an error.
func (f *File) Delete(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.path == "" {
		return errors.New("persist: empty file path")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	err := os.Remove(f.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("persist: delete %s: %w", f.path, err)
	}
	return nil
}
