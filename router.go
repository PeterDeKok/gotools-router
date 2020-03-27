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

type RestConfig struct {
	Listen string
	Port   int

	Cert string
	Priv string

	User string
	Pass string

	RequestLogLevel string
}

type Router struct {
	*httprouter.Router

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

var (
	log logger.Logger
	cnf = &RestConfig{}
)

func init() {
	log = logger.New("router")
	config.Add(&struct{ Rest *RestConfig }{cnf})
}

func New() *Router {
	rtr := httprouter.New()

	rtr.RedirectTrailingSlash = true

	rtr.MethodNotAllowed = handler.ErrorHandlerFactory("verb not allowed", 405)
	rtr.NotFound = handler.ErrorHandlerFactory("route not found", 404)

	return &Router{
		Router: rtr,

		StaticRootHandlers: make(map[string]http.Handler),
	}
}

func NewSPA(spaHandler, distHandler http.Handler) *Router {
	rtr := New()

	rtr.SpaHandler = spaHandler
	rtr.DistHandler = distHandler
	rtr.DistPrefix = "dist"
	rtr.RouterPrefix = "api"

	rtr.StaticRootHandlers["/favicon.ico"] = distHandler

	return rtr
}

func (rtr *Router) Serve() {
	// Link the main parts (frontend and API)
	routerPrefix := "/" + strings.Trim(rtr.RouterPrefix, "/")

	http.Handle(strings.TrimRight(routerPrefix, "/")+"/", http.StripPrefix(routerPrefix, rtr.requestLogger()))

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

func (rtr *Router) requestLogger() http.Handler {
	return requestLogger(rtr)
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
