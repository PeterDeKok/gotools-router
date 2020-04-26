package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"peterdekok.nl/gotools/config"
	"peterdekok.nl/gotools/logger"
	"peterdekok.nl/gotools/router/handler"
	"peterdekok.nl/gotools/router/tls"
	"peterdekok.nl/gotools/trap"
	"strings"
	"time"
)

type Router struct {
	Routable

	// Catchall for SPA (e.g.: index.html)
	SpaHandler   http.Handler

	// Dist folder (for static files like js, css, images, etc.)
	DistHandler  http.Handler
	DistPrefix   string

	// Prefix for router (API, websocket, custom go handlers, etc.)
	RouterPrefix string

	// Handlers for specific handlers that should be accessible outside dist/router (e.g.: favicon.ico)
	StaticRootHandlers map[string]http.Handler
}

type HttpRouter struct {
	*httprouter.Router
}

type RestConfig struct {
	Listen string
	Port   int

	Cert string
	Priv string

	User string
	Pass string

	RequestLogLevel string
}

type SPAConfig struct {
	SpaHandler http.Handler
	DistHandler http.Handler

	DistPrefix string
	RouterPrefix string

	StaticRootHandlers map[string]http.Handler
}

type Routable interface {
	// ServeHTTP will propagate to the nearest actual router
	ServeHTTP(w http.ResponseWriter, r *http.Request)

	// GET is a shortcut for router.Handle(http.MethodGet, path, handle)
	GET(path string, handle httprouter.Handle)

	// HEAD is a shortcut for router.Handle(http.MethodHead, path, handle)
	HEAD(path string, handle httprouter.Handle)

	// OPTIONS is a shortcut for router.Handle(http.MethodOptions, path, handle)
	OPTIONS(path string, handle httprouter.Handle)

	// POST is a shortcut for router.Handle(http.MethodPost, path, handle)
	POST(path string, handle httprouter.Handle)

	// PUT is a shortcut for router.Handle(http.MethodPut, path, handle)
	PUT(path string, handle httprouter.Handle)

	// PATCH is a shortcut for router.Handle(http.MethodPatch, path, handle)
	PATCH(path string, handle httprouter.Handle)

	// DELETE is a shortcut for router.Handle(http.MethodDelete, path, handle)
	DELETE(path string, handle httprouter.Handle)

	// Handle registers a new request handle with the given path and method.
	//
	// For GET, POST, PUT, PATCH and DELETE requests the respective shortcut
	// functions can be used.
	//
	// This function is intended for bulk loading and to allow the usage of less
	// frequently used, non-standardized or custom methods (e.g. for internal
	// communication with a proxy).
	Handle(method, path string, handle httprouter.Handle)

	// Handler is an adapter which allows the usage of an http.Handler as a
	// request handle.
	// The Params are available in the request context under ParamsKey.
	Handler(method, path string, handler http.Handler)

	// HandlerFunc is an adapter which allows the usage of an http.HandlerFunc as a
	// request handle.
	HandlerFunc(method, path string, handler http.HandlerFunc)

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
	ServeFiles(path string, root http.FileSystem)

	// Lookup allows the manual lookup of a method + path combo.
	// This is e.g. useful to build a framework around this router.
	// If the path was found, it returns the handle function and the path parameter
	// values. Otherwise the third return value indicates whether a redirection to
	// the same path with an extra / without the trailing slash should be performed.
	Lookup(method, path string) (httprouter.Handle, httprouter.Params, bool)

	Prefix(prefix string) *PrefixRouter

	PrefixFunc(prefix string, fn func(rr Routable)) *PrefixRouter
}

var (
	log logger.Logger
	cnf = &RestConfig{}
)

func init() {
	log = logger.New("router")
	config.Add(&struct{ Rest *RestConfig }{cnf})
}

func New() *Router {
	rtr := &HttpRouter{httprouter.New()}

	rtr.RedirectTrailingSlash = true

	rtr.MethodNotAllowed = handler.ErrorHandlerFactory("verb not allowed", 405)
	rtr.NotFound = handler.ErrorHandlerFactory("route not found", 404)

	return &Router{
		Routable: rtr,

		StaticRootHandlers: make(map[string]http.Handler),
	}
}

func NewSPA(spaConfig SPAConfig) *Router {
	rtr := New()

	if spaConfig.SpaHandler != nil {
		rtr.SpaHandler = spaConfig.SpaHandler
	}

	if spaConfig.DistHandler != nil {
		rtr.DistHandler = spaConfig.DistHandler
		rtr.StaticRootHandlers["/favicon.ico"] = spaConfig.DistHandler
	}

	if len(spaConfig.DistPrefix) > 0 {
		rtr.DistPrefix = spaConfig.DistPrefix
	} else {
		rtr.DistPrefix = "dist"
	}

	if len(spaConfig.RouterPrefix) > 0 {
		rtr.RouterPrefix = spaConfig.RouterPrefix
	} else {
		rtr.RouterPrefix = "api"
	}

	if spaConfig.StaticRootHandlers != nil {
		for k, h := range spaConfig.StaticRootHandlers {
			rtr.StaticRootHandlers[k] = h
		}
	}

	rtr.Routable = rtr.Routable.Prefix(rtr.RouterPrefix)

	return rtr
}

func (rtr *Router) Serve() {
	// Link the main parts (frontend and API)
	routerPrefix := "/" + strings.Trim(rtr.RouterPrefix, "/")

	http.Handle(strings.TrimRight(routerPrefix, "/")+"/", rtr.requestLogger())

	if rtr.DistHandler != nil {
		distPrefix := "/" + strings.Trim(rtr.DistPrefix, "/")

		http.Handle(strings.TrimRight(distPrefix, "/")+"/", http.StripPrefix(distPrefix, requestLogger(rtr.DistHandler)))
	}

	if rtr.SpaHandler != nil {
		http.Handle("/", requestLogger(rtr.SpaHandler))
	}

	for p, h := range rtr.StaticRootHandlers {
		http.Handle("/"+strings.TrimLeft(p, "/"), http.StripPrefix("/", requestLogger(h)))
	}

	// Initialize the server
	addr := fmt.Sprintf("%v:%v", cnf.Listen, cnf.Port)

	l := log.WithField("addr", addr)

	server := &http.Server{
		Addr: addr,
	}

	// Cleanly shutdown server
	trap.OnKill(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			log.WithField("addr", addr).WithError(err).Error("failed to shutdown server")
		}
	})

	// Boot the server
	if len(cnf.Cert) > 0 || len(cnf.Priv) > 0 {
		l = l.WithField("TLS", "Yes")

		// Watch for changes in the certificate
		tlsWatcher, err := tls.NewWatcher(cnf.Cert, cnf.Priv)

		if err != nil {
			l.WithError(err).Error("Failed to setup TLS certificate watcher")

			panic(err)
		}

		// Cleanly stop certificate watcher
		trap.OnKill(func() {
			if err := tlsWatcher.Stop(); err != nil {
				l.WithError(err).Error("failed to stop tls watcher")
			}
		})

		server.TLSConfig = tlsWatcher.TLSConfig

		l.Info("Starting ListenAndServe")

		if err := tlsWatcher.Start(); err != nil {
			l.WithError(err).Error("Failed to start TLS certificate watcher")

			panic(err)
		}

		if err := server.ListenAndServeTLS(cnf.Cert, cnf.Priv); err != nil && err != http.ErrServerClosed {
			l.WithError(err).Error("server error")

			panic(err)
		}
	} else {
		l = l.WithField("TLS", "No")

		l.Info("Starting ListenAndServe")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.WithError(err).Error("server error")

			panic(err)
		}
	}
}

func (rtr *Router) Prefix(prefix string) *PrefixRouter {
	return NewPrefixRouter(rtr, prefix)
}

func (rtr *Router) PrefixFunc(prefix string, fn func(rr Routable)) *PrefixRouter {
	pr := rtr.Prefix(prefix)

	fn(pr)

	return pr
}

func (rtr *Router) requestLogger() http.Handler {
	return requestLogger(rtr)
}

func (hr *HttpRouter) Prefix(prefix string) *PrefixRouter {
	return NewPrefixRouter(hr, prefix)
}

func (hr *HttpRouter) PrefixFunc(prefix string, fn func(rr Routable)) *PrefixRouter {
	pr := hr.Prefix(prefix)

	fn(pr)

	return pr
}

func requestLogger(wrapped http.Handler) http.Handler {
	level, err := logrus.ParseLevel(cnf.RequestLogLevel)

	if err != nil && len(cnf.RequestLogLevel) > 0 {
		log.WithField("level", cnf.RequestLogLevel).WithError(err).Error("Invalid request log level")
	}

	return handler.MiddleWareHandlerFactory(func(w http.ResponseWriter, r *http.Request) {
		// Log the request if applicable
		if level >= logrus.ErrorLevel {
			l := log.WithFields(logrus.Fields{
				"method":        r.Method,
				"time":          time.Now().Format("2006-01-02 15:04:05"),
				"uri":           r.RequestURI,
				"contentlength": r.ContentLength,
			})

			if level >= logrus.InfoLevel {
				l = l.WithFields(logrus.Fields{
					"ip":        r.RemoteAddr,
					"useragent": r.UserAgent(),
					"referer":   r.Referer(),
				})

				if level >= logrus.DebugLevel {
					// Don't directly log from the headers
					// printHeaders() will strip away known credentials,
					// when more credentials are expected, those should be replaced as well!
					l = l.WithFields(logrus.Fields{
						"headers": printHeaders(r.Header),
					})

					if level >= logrus.TraceLevel && r.Body != nil {
						bodyBytes, err := ioutil.ReadAll(r.Body)

						if err != nil {
							// This would be quite problematic,
							// as it is unknown if the request body was modified
							// and there is no way to reset it
							log.WithError(err).Error("Failed to read request body for logging")

							w.WriteHeader(500)

							return
						}

						// Restore the io.ReadCloser to its original state
						r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

						l = l.WithField("body", string(bodyBytes))

						// Also print using fmt, so the newlines will be better visible
						fmt.Println("Body:\n" + string(bodyBytes) + "\n\n")
					}
				}
			}

			l.Info("Request received")
		}

		// Delegate request to the given handler
		wrapped.ServeHTTP(w, r)
	})
}

func BasicAuth(h httprouter.Handle) httprouter.Handle {
	requiredUser := cnf.User
	requiredPass := cnf.Pass

	if len(requiredUser) < 6 || len(requiredPass) < 20 {
		err := errors.New("failed to protect route with basic auth")

		log.WithError(err).Error("User should be at least 6 chars and pass at least 20")

		panic(err)
	}

	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get the Basic Authentication credentials
		user, password, hasAuth := r.BasicAuth()

		if hasAuth && user == requiredUser && password == requiredPass {
			// Delegate request to the given handle
			h(w, r, ps)
		} else {
			if hasAuth {
				log.WithFields(logrus.Fields{
					"uri":  r.RequestURI,
					"ip":   r.RemoteAddr,
					"user": user,
				}).Error("Basic Auth failed: Invalid credentials")
			}

			// Request Basic Authentication otherwise
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}

func printHeaders(headers http.Header) http.Header {
	newMap := make(http.Header)

	for k := range headers {
		newMap[k] = make([]string, 0)
	}

	for k, v := range headers {
		for _, val := range v {
			kl := strings.ToLower(k)

			if kl == "authorization" || kl == "auth" || kl == "password" || kl == "pass" {
				val = "...REMOVED..."
			}

			newMap[k] = append(newMap[k], val)
		}
	}

	return newMap
}