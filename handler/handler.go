package handler

import (
	"net/http"
	"peterdekok.nl/gotools/logger"
)

type Handler struct {
	cb func(w http.ResponseWriter, r *http.Request)
}

var (
	log logger.Logger
)

func init() {
	log = logger.New("router.handler")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.cb(w, r)
}

func ErrorHandlerFactory(msg string, code int) http.Handler {
	return &Handler{
		cb: func(w http.ResponseWriter, r *http.Request) {
			log.WithField("verb", r.Method).
				WithField("uri", r.RequestURI).
				WithField("msg", msg).
				Error("Incorrect request")

			w.WriteHeader(code)
		},
	}
}

func MiddleWareHandlerFactory(cb func(http.ResponseWriter, *http.Request)) http.Handler {
	return &Handler{
		cb: cb,
	}
}
