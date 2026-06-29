// Package httpx provides the consistent API response/error envelope used by all
// handlers, plus helpers for decoding and validating request bodies.
package httpx

import (
	"encoding/json"
	"net/http"
	"time"
)

// Error codes returned to clients. Stable strings the frontend can switch on.
const (
	CodeValidation   = "VALIDATION_ERROR"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeForbidden    = "FORBIDDEN"
	CodeNotFound     = "NOT_FOUND"
	CodeConflict     = "CONFLICT"
	CodeRateLimited  = "RATE_LIMITED"
	CodeBadRequest   = "BAD_REQUEST"
	CodeInternal     = "INTERNAL_ERROR"
)

// APIError is a structured, client-facing error carrying its HTTP status.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// Details optionally carries field-level validation errors.
	Details any `json:"details,omitempty"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// NewError builds an APIError.
func NewError(status int, code, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

// Common constructors.
func ErrValidation(message string, details any) *APIError {
	return &APIError{Status: http.StatusUnprocessableEntity, Code: CodeValidation, Message: message, Details: details}
}
func ErrUnauthorized(message string) *APIError {
	return NewError(http.StatusUnauthorized, CodeUnauthorized, orDefault(message, "authentication required"))
}
func ErrForbidden(message string) *APIError {
	return NewError(http.StatusForbidden, CodeForbidden, orDefault(message, "you do not have access to this resource"))
}
func ErrNotFound(message string) *APIError {
	return NewError(http.StatusNotFound, CodeNotFound, orDefault(message, "resource not found"))
}
func ErrConflict(message string) *APIError {
	return NewError(http.StatusConflict, CodeConflict, message)
}
func ErrBadRequest(message string) *APIError {
	return NewError(http.StatusBadRequest, CodeBadRequest, message)
}
func ErrInternal() *APIError {
	return NewError(http.StatusInternalServerError, CodeInternal, "an internal error occurred")
}

// envelope shapes.
type successEnvelope struct {
	Data any  `json:"data"`
	Meta meta `json:"meta"`
}
type errorEnvelope struct {
	Error *APIError `json:"error"`
}
type meta struct {
	Timestamp string `json:"timestamp"`
}

// PageMeta is the pagination block for list responses.
type PageMeta struct {
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	Total     int    `json:"total"`
	Timestamp string `json:"timestamp"`
}
type paginatedEnvelope struct {
	Data any      `json:"data"`
	Meta PageMeta `json:"meta"`
}

// WriteSuccess writes a `{ "data": ..., "meta": { timestamp } }` body.
func WriteSuccess(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, successEnvelope{Data: data, Meta: meta{Timestamp: now()}})
}

// WritePaginated writes a `{ "data": [...], "meta": { page, per_page, total } }` body.
func WritePaginated(w http.ResponseWriter, data any, page, perPage, total int) {
	writeJSON(w, http.StatusOK, paginatedEnvelope{
		Data: data,
		Meta: PageMeta{Page: page, PerPage: perPage, Total: total, Timestamp: now()},
	})
}

// WriteError writes the error envelope. Non-APIError values become 500s.
func WriteError(w http.ResponseWriter, err error) {
	apiErr, ok := err.(*APIError)
	if !ok {
		apiErr = ErrInternal()
	}
	writeJSON(w, apiErr.Status, errorEnvelope{Error: apiErr})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
