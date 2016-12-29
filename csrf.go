// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

/*
Package csrfmidware is a HTTP middleware that provides Cross-Site Request
Forgery protection for Gem web framework.

This package requires csrf package: https://github.com/gorilla/csrf.

Example
	package main

	import (
		"fmt"
		"html/template"

		"github.com/go-gem/gem"
		"github.com/go-gem/middleware-csrf"
		"github.com/gorilla/csrf"
	)

	var form = `
    <html>
    <head>
    	<title>Sign Up!</title>
    </head>
    <body>
    	<form method="POST" action="/signup" accept-charset="UTF-8">
    		<input type="text" name="name">
    		<input type="text" name="email">
    		<!--
        	The default template tag used by the CSRF middleware .
        	This will be replaced with a hidden <input> field containing the
       		masked CSRF token.
    		-->
    		{{ .csrfField }}
   		<input type="submit" value="Sign up!">
	</form>
    </body>
    </html>
    `

	var (
		t = template.Must(template.New("signup_form.tmpl").Parse(form))

		// Don't forget to pass csrf.Secure(false) if you're developing locally
		// over plain HTTP (just don't leave it on in production).
		csrfMiddleware = csrfmidware.New([]byte("32-byte-long-auth-key"), csrf.Secure(false))
	)

	func main() {
		router := gem.NewRouter()
		router.Use(csrfMiddleware)
		router.GET("/", showSignupForm)
		router.POST("/signup", submitSignupForm)

		gem.ListenAndServe(":8080", router.Handler())
	}

	func showSignupForm(ctx *gem.Context) {
		// signup_form.tmpl just needs a {{ .csrfField }} template tag for
		// csrf.TemplateField to inject the CSRF token into. Easy!
		t.ExecuteTemplate(ctx, "signup_form.tmpl", map[string]interface{}{
			csrf.TemplateTag: csrf.TemplateField(ctx.Request),
		})
	}

	func submitSignupForm(ctx *gem.Context) {
		// We can trust that requests making it this far have satisfied
		// our CSRF protection requirements.
		fmt.Fprintf(ctx, "%v\n", ctx.Request.PostForm)
	}
*/
package csrfmidware

import (
	"net/http"

	"github.com/go-gem/gem"
	"github.com/gorilla/csrf"
)

const (
	cookieName = "_csrf"
	formName   = "_csrf"
)

// New return a CSRF middleware via the given secret key
// and default option.
func New(secret []byte, opts ...csrf.Option) *CSRF {
	opts = append([]csrf.Option{
		csrf.CookieName(cookieName),
		csrf.CookieName(formName),
	}, opts...)

	return &CSRF{
		handler: csrf.Protect(secret, opts...),
	}
}

// CSRF is a HTTP middleware that provides Cross-Site Request Forgery
// protection.
//
// It securely generates a masked (unique-per-request) token that
// can be embedded in the HTTP response (e.g. form field or HTTP header).
// The original (unmasked) token is stored in the session, which is inaccessible
// by an attacker (provided you are using HTTPS). Subsequent requests are
// expected to include this token, which is compared against the session token.
// Requests that do not provide a matching token are served with a HTTP 403
// 'Forbidden' error response.
type CSRF struct {
	handler func(http.Handler) http.Handler
}

// Wrap implements the Middleware interface.
func (c *CSRF) Wrap(next gem.Handler) gem.Handler {
	return gem.HandlerFunc(func(ctx *gem.Context) {
		c.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx.Request = r
			next.Handle(ctx)
		})).ServeHTTP(ctx.Response, ctx.Request)
	})
}
