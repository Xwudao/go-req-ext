package persist

import (
	"context"
	"errors"
	"testing"
)

func TestStoreFunc(t *testing.T) {
	ctx := context.Background()
	var saved []byte

	store := StoreFunc{
		LoadFunc: func(context.Context) ([]byte, error) {
			return append([]byte(nil), saved...), nil
		},
		SaveFunc: func(_ context.Context, data []byte) error {
			saved = append([]byte(nil), data...)
			return nil
		},
		DeleteFunc: func(context.Context) error {
			saved = nil
			return nil
		},
	}

	if err := store.Save(ctx, []byte("v")); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v" {
		t.Fatalf("Load = %q", got)
	}
	if err := store.Delete(ctx); err != nil {
		t.Fatal(err)
	}

	var empty StoreFunc
	if _, err := empty.Load(ctx); err == nil {
		t.Fatal("expected error from nil LoadFunc")
	}
	if err := empty.Save(ctx, nil); err == nil {
		t.Fatal("expected error from nil SaveFunc")
	}
	if err := empty.Delete(ctx); err == nil {
		t.Fatal("expected error from nil DeleteFunc")
	}
}

func TestNilStore(t *testing.T) {
	if err := SaveJSON(context.Background(), nil, struct{}{}); err == nil {
		t.Fatal("expected error for nil store")
	}
	var v any
	if err := LoadJSON(context.Background(), nil, &v); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestLoadJSONInvalid(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	if err := store.Save(ctx, []byte("{")); err != nil {
		t.Fatal(err)
	}
	var v any
	err := LoadJSON(ctx, store, &v)
	if err == nil || errors.Is(err, ErrNotExist) {
		t.Fatalf("LoadJSON invalid = %v, want decode error", err)
	}
}
