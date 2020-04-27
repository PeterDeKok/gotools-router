package router

import (
	"context"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"strings"
)

type Middleware func(wrapped httprouter.Handle) httprouter.Handle

type PrefixRouter struct {
	Routable

	prefix string

	middleware Middleware
}

func NewPrefixRouter(r Routable, prefix string, middleware Middleware) *PrefixRouter {
	prefix = strings.TrimRight("/"+strings.Trim(prefix, "/"), "/")

	return &PrefixRouter{
		Routable:   r,
		prefix:     prefix,
		middleware: middleware,
	}
}

func (pr *PrefixRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pr.Routable.ServeHTTP(w, r)
}

// GET is a shortcut for router.Handle(http.MethodGet, path, handle)
func (pr *PrefixRouter) GET(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodGet, path, handle)
}

// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
func (pr *PrefixRouter) HEAD(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodHead, path, handle)
}

// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
func (pr *PrefixRouter) OPTIONS(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodOptions, path, handle)
}

// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
func (pr *PrefixRouter) POST(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodPost, path, handle)
}

// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
func (pr *PrefixRouter) PUT(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodPut, path, handle)
}

// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
func (pr *PrefixRouter) PATCH(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodPatch, path, handle)
}

// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
func (pr *PrefixRouter) DELETE(path string, handle httprouter.Handle) {
	pr.Handle(http.MethodDelete, path, handle)
}

// Handle registers a new request handle with the given path and method.
//
// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
// functions can be used.
//
// This function is intended for bulk loading and to allow the usage of less
// frequently used, non-standardized or custom methods (e.g. for internal
// communication with a proxy).
func (pr *PrefixRouter) Handle(method, path string, handle httprouter.Handle) {
	if len(path) == 0 {
		path = pr.prefix
	} else {
		path = pr.prefix + "/" + strings.TrimLeft(path, "/")
	}

	if pr.middleware != nil {
		handle = pr.middleware(handle)
	}

	pr.Routable.Handle(method, path, handle)
}

// Handler is an adapter which allows the usage of an http.Handler as a
// request handle.
// The Params are available in the request context under ParamsKey.
func (pr *PrefixRouter) Handler(method, path string, handler http.Handler) {
	pr.Handle(method, path, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if len(p) > 0 {
			ctx := r.Context()
			ctx = context.WithValue(ctx, httprouter.ParamsKey, p)
			r = r.WithContext(ctx)
		}
		handler.ServeHTTP(w, r)
	})
}

// HandlerFunc is an adapter which allows the usage of an http.HandlerFunc as a
// request handle.
func (pr *PrefixRouter) HandlerFunc(method, path string, handler http.HandlerFunc) {
	pr.Handler(method, path, handler)
}

// ServeFiles serves files from the given file system root.
// The path must end with "/*filepath", files are then served from the local
// path /defined/root/dir/*filepath.
// For example if root is "/etc" and *filepath is "passwd", the local file
// "/etc/passwd" would be served.
// Internally a http.FileServer is used, therefore http.NotFound is used instead
// of the Router's NotFound handler.
// To use the operating system's file system implementation,
// use http.Dir:
//     router.ServeFiles("/src/*filepath", http.Dir("/var/www"))
func (pr *PrefixRouter) ServeFiles(path string, root http.FileSystem) {
	if pr.middleware != nil {
		panic("ServeFiles not available with middleware")
	}

	if len(path) == 0 {
		path = pr.prefix
	} else {
		path = pr.prefix + "/" + strings.TrimLeft(path, "/")
	}

	pr.Routable.ServeFiles(path, root)
}

// Lookup allows the manual lookup of a method + path combo.
// This is e.g. useful to build a framework around this router.
// If the path was found, it returns the handle function and the path parameter
// values. Otherwise the third return value indicates whether a redirection to
// the same path with an extra / without the trailing slash should be performed.
func (pr *PrefixRouter) Lookup(method, path string) (httprouter.Handle, httprouter.Params, bool) {
	if len(path) == 0 {
		path = pr.prefix
	} else {
		path = pr.prefix + "/" + strings.TrimLeft(path, "/")
	}

	handle, params, redirectTrailing := pr.Routable.Lookup(method, path)

	if pr.middleware != nil {
		handle = pr.middleware(handle)
	}

	return handle, params, redirectTrailing
}

// Wraps the current prefix router and adds a prefix to the path
// for all handlers registered through this wrapper.
func (pr *PrefixRouter) Prefix(prefix string) *PrefixRouter {
	return NewPrefixRouter(pr, prefix, nil)
}

// Wraps the current prefix router and adds a prefix to the path
// for all handlers registered through this wrapper.
// The wrapper is passed to a callback, to create a nice grouped
// structure to the code.
func (pr *PrefixRouter) PrefixFunc(prefix string, fn func(rr Routable)) *PrefixRouter {
	ppr := pr.Prefix(prefix)

	fn(ppr)

	return ppr
}

// Wraps the current prefix router and adds middleware
// for all handlers registered through this wrapper.
func (pr *PrefixRouter) Middleware(middleware Middleware) *PrefixRouter {
	return NewPrefixRouter(pr, "", middleware)
}

// The wrapper (prefix router) is passed to a callback,
// to create a nice grouped structure to the code.
func (pr *PrefixRouter) Group(fn func(rr Routable)) *PrefixRouter {
	fn(pr)

	return pr
}
