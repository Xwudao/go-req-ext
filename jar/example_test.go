package jar_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Xwudao/go-req-ext/jar"
	"github.com/Xwudao/go-req-ext/persist"
)

func Example() {
	ctx := context.Background()
	store := persist.NewFile("cookies.json")

	j, err := jar.Open(ctx, jar.WithStore(store), jar.WithAutoSave(2*time.Second))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer j.Close()

	client := &http.Client{Jar: j}
	_, _ = client.Get("https://example.com/")
}

func ExampleNew() {
	j, err := jar.New()
	if err != nil {
		fmt.Println(err)
		return
	}

	u, _ := url.Parse("https://example.com/account/login")
	j.SetCookies(u, []*http.Cookie{
		{Name: "session", Value: "abc", Path: "/", HttpOnly: true},
	})

	for _, c := range j.Cookies(u) {
		fmt.Println(c.Name, c.Value)
	}
	// Output: session abc
}
