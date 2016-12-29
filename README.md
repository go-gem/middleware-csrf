# CSRF Middleware

[![Build Status](https://travis-ci.org/go-gem/middleware-csrf.svg?branch=master)](https://travis-ci.org/go-gem/middleware-csrf)
[![GoDoc](https://godoc.org/github.com/go-gem/middleware-csrf?status.svg)](https://godoc.org/github.com/go-gem/middleware-csrf)
[![Coverage Status](https://coveralls.io/repos/github/go-gem/middleware-csrf/badge.svg?branch=master)](https://coveralls.io/github/go-gem/middleware-csrf?branch=master)

CSRF middleware is a HTTP middleware that provides Cross-Site Request
Forgery protection for [Gem](https://github.com/go-gem/gem) Web framework.

## Getting Started

**Install**

```
$ go get -u github.com/go-gem/middleware-csrf
```

**Example**

```
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
```