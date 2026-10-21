package persist

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMemory(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.Load(ctx); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Load on empty store = %v, want ErrNotExist", err)
	}

	data := []byte("hello")
	if err := store.Save(ctx, data); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X' // Store must copy its input.

	got, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("Load = %q, want hello", got)
	}

	got[0] = 'Y' // Load must return a copy.
	again, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != "hello" {
		t.Fatalf("second Load = %q, want hello", again)
	}

	if err := store.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Load after Delete = %v, want ErrNotExist", err)
	}
}

func TestFile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	store := NewFile(path)

	if _, err := store.Load(ctx); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Load on missing file = %v, want ErrNotExist", err)
	}

	if err := store.Save(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, []byte("two")); err != nil {
		t.Fatal(err)
	}

	got, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("Load = %q, want two", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("file mode = %o, want 600", mode)
		}
	}

	if err := store.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx); err != nil {
		t.Fatalf("second Delete = %v, want nil", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Load after Delete = %v, want ErrNotExist", err)
	}
}

func TestFileOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.bin")
	store := NewFile(path, WithFileMode(0o640), WithDirMode(0o750))
	if store.Path() != path {
		t.Fatalf("Path = %q, want %q", store.Path(), path)
	}
	if err := store.Save(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o640 {
			t.Fatalf("file mode = %o, want 640", mode)
		}
	}
}

func TestJSON(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	type payload struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	if err := SaveJSON(ctx, store, payload{Name: "a", N: 1}); err != nil {
		t.Fatal(err)
	}

	var got payload
	if err := LoadJSON(ctx, store, &got); err != nil {
		t.Fatal(err)
	}
	if got != (payload{Name: "a", N: 1}) {
		t.Fatalf("payload = %+v", got)
	}

	empty := NewMemory()
	var missing payload
	if err := LoadJSON(ctx, empty, &missing); !errors.Is(err, ErrNotExist) {
		t.Fatalf("LoadJSON missing = %v, want ErrNotExist", err)
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := NewFile(filepath.Join(t.TempDir(), "state"))
	if _, err := store.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load = %v, want context.Canceled", err)
	}
	if err := store.Save(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save = %v, want context.Canceled", err)
	}
	if err := store.Delete(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete = %v, want context.Canceled", err)
	}
}
