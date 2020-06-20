package writer

import (
	"encoding/json"
	"net/http"
	"peterdekok.nl/gotools/logger"
)

type JSONError struct {
	Code        int			`json:"code"`
	Description interface{} `json:"description"`
	internalMsg error
}

var (
	log logger.Logger
	JsonInternalServerError = &JSONError{
		Code:        http.StatusInternalServerError,
		Description: http.StatusText(http.StatusInternalServerError),
	}
)

func init() {
	log = logger.New("router.writer")
}

func NewJsonError(code int, description interface{}, internalMsg error) *JSONError {
	if description == nil {
		description = http.StatusText(code)
	}

	if str, ok := description.(string); ok && len(str) == 0 {
		description = "Unknown error"
	}

	return &JSONError{
		Code:        code,
		Description: description,
		internalMsg: internalMsg,
	}
}

func Json(w http.ResponseWriter, l logger.Logger, code int, body interface{}) error {
	b, err := json.Marshal(body)

	if err != nil {
		return NewJsonError(http.StatusInternalServerError, "Failed to marshal json", err).Write(w, l)
	}

	w.WriteHeader(code)

	if _, err := w.Write(b); err != nil {
		return NewJsonError(http.StatusInternalServerError, "Failed to write json", err).Write(w, l)
	}

	return nil
}

func (je *JSONError) Error() string {
	return je.internalMsg.Error()
}

func (je *JSONError) Marshal() (int, []byte, error) {
	b, err := json.Marshal(je)

	if err != nil {
		b, err = json.Marshal(JsonInternalServerError)

		return JsonInternalServerError.Code, b, err
	}

	return je.Code, b, nil
}

func (je *JSONError) Write(w http.ResponseWriter, l logger.Logger) error {
	l.WithField("statuscode", je.Code).WithError(je).Warn(je.Description)

	code, b, err := je.Marshal()

	if err != nil {
		l.WithError(err).Error("Failed to write json error")

		return err
	}

	http.Error(w, string(b), code)

	return je
}
