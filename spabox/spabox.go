package spabox

import (
	"encoding/json"
	"github.com/markbates/pkger"
	"net/http"
	"peterdekok.nl/gotools/logger"
	"peterdekok.nl/gotools/router/handler"
	"strings"
)

type SpaBox struct {
	box pkger.Dir
	cnf Config
}

type Config struct {
	// Path to dist directory is always relative to the root of current module
	PathToDist string

	// Path to Index is the relative path
	PathToIndex         string
	PathToIndexAbsolute bool
}

type JsonErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var (
	log logger.Logger
)

func init() {
	log = logger.New("spabox")
}

func New(cnf Config) *SpaBox {
	return &SpaBox{
		box: pkger.Dir(cnf.PathToDist),
		cnf: cnf,
	}
}

func (sb *SpaBox) IndexHandler() http.Handler {
	return handler.MiddleWareHandlerFactory(func(w http.ResponseWriter, r *http.Request) {
		if len(sb.cnf.PathToIndex) == 0 {
			sb.cnf.PathToIndex = "index.html"
		}

		pathToIndex := "/" + strings.Trim(sb.cnf.PathToIndex, "/")

		if !sb.cnf.PathToIndexAbsolute {
			pathToIndex = strings.TrimRight(sb.cnf.PathToDist, "/") + pathToIndex
		}

		f, err := pkger.Open(pathToIndex)
		//f, err := sb.box.Open(sb.cnf.PathToIndex)

		if err != nil {
			log.WithError(err).Error("Failed to open index")

			http.NotFound(w, r)

			return
		}

		d, err := f.Stat()

		if err != nil {
			log.WithError(err).Error("Failed to get file info for index")

			http.NotFound(w, r)

			return
		}

		http.ServeContent(w, r, d.Name(), d.ModTime(), f)

		return
	})
}

func (sb *SpaBox) DistHandler() http.Handler {
	return http.FileServer(sb.box)
}

func JsonError(w http.ResponseWriter, _ *http.Request, err error, code int) error {
	var (
		b    []byte
		ierr error
	)

	if x, ok := err.(interface{ Code() int }); ok {
		code = x.Code()
	}

	// If code >= 500 or code < 200 -> Obfuscate error string -> server error
	if code < 200 {
		b, ierr = json.Marshal(JsonErr{
			Code:    500,
			Message: "Server error",
		})
	} else if code >= 500 {
		b, ierr = json.Marshal(JsonErr{
			Code:    code,
			Message: "Server error",
		})
	} else if x, ok := err.(json.Unmarshaler); ok {
		b, ierr = json.Marshal(x)
	} else {
		b, ierr = json.Marshal(JsonErr{
			Code:    code,
			Message: err.Error(),
		})
	}

	w.WriteHeader(code)

	if ierr == nil {
		_, ierr = w.Write(b)
	}

	if ierr != nil {
		log.WithError(ierr).Error("Failed to write error to response writer")

		return err
	}

	return nil
}
