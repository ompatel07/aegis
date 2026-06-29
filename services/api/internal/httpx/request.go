package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-playground/validator/v10"
)

// validate is a shared, thread-safe validator instance.
var validate = validator.New(validator.WithRequiredStructEnabled())

const maxBodyBytes = 1 << 20 // 1 MiB

// DecodeAndValidate reads a JSON body into dst (size-limited, strict) and runs
// struct validation. It returns a ready-to-write *APIError on any failure.
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) *APIError {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			return ErrBadRequest("request body too large")
		case errors.Is(err, io.EOF):
			return ErrBadRequest("request body is empty")
		default:
			return ErrBadRequest(fmt.Sprintf("malformed JSON: %s", err.Error()))
		}
	}
	// Reject trailing garbage after the JSON object.
	if dec.More() {
		return ErrBadRequest("request body must contain a single JSON object")
	}

	if err := validate.Struct(dst); err != nil {
		return ErrValidation("request validation failed", fieldErrors(err))
	}
	return nil
}

// fieldErrors converts validator errors into a {field: rule} map for clients.
func fieldErrors(err error) map[string]string {
	out := map[string]string{}
	var verrs validator.ValidationErrors
	if errors.As(err, &verrs) {
		for _, fe := range verrs {
			out[fe.Field()] = fe.Tag()
		}
	}
	return out
}

// QueryInt reads an integer query param, clamped to [min, max], with a default.
func QueryInt(r *http.Request, key string, def, min, max int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}
