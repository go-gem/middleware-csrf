// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package csrfmidware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-gem/gem"
	"github.com/gorilla/csrf"
)

func TestCSRF(t *testing.T) {
	fieldName := "_csrf"
	csrfMidware := New([]byte("32-byte-long-auth-key"), csrf.FieldName(fieldName))

	// index handler for getting the masked csrf token.
	var masked string
	index := csrfMidware.Wrap(gem.HandlerFunc(func(ctx *gem.Context) {
		masked = csrf.Token(ctx.Request)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	ctx := &gem.Context{Request: req, Response: resp}
	index.Handle(ctx)
	if masked == "" {
		t.Fatal("failed to get masked csrf token")
	}

	// sign in handler
	var pass bool
	signIn := csrfMidware.Wrap(gem.HandlerFunc(func(ctx *gem.Context) {
		pass = true
	}))

	// send a request without masked csrf token
	ctx.Request.Method = "POST"
	signIn.Handle(ctx)
	if pass {
		t.Error("expected no pass the sign in handler, but passed")
	}

	// send a request with masked csrf token.
	ctx.Request.PostForm = url.Values{
		fieldName: []string{masked},
	}
	// add cookie.
	cookies := strings.Split(ctx.Response.Header().Get("Set-Cookie"), ";")
	var cookieValue string
	for _, v := range cookies {
		if len(v) > len(fieldName) {
			if fieldName == v[:len(fieldName)] {
				cookieValue = v[len(fieldName)+1:]
				break
			}
		}
	}
	if cookieValue == "" {
		t.Fatal("failed to get cookie")
	}

	ctx.Request.AddCookie(&http.Cookie{
		Name:  fieldName,
		Value: cookieValue,
	})
	signIn.Handle(ctx)
	if !pass {
		t.Error("failed to pass the sign in handler")
	}
}
