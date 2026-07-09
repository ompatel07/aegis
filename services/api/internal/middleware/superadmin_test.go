package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireSuperAdminBlocksNonAdmin(t *testing.T) {
	mw := RequireSuperAdmin(func(ctx context.Context, userID string) (bool, error) { return false, nil })
	rr := httptest.NewRecorder()
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/admin/overview", nil)
	req = req.WithContext(WithUser(req.Context(), "user-1", "user"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if called {
		t.Fatalf("downstream handler must not run for a non-admin")
	}
}

func TestRequireSuperAdminAllowsAdmin(t *testing.T) {
	mw := RequireSuperAdmin(func(ctx context.Context, userID string) (bool, error) {
		if userID != "admin-1" {
			t.Fatalf("checker got userID %q", userID)
		}
		return true, nil
	})
	rr := httptest.NewRecorder()
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))

	req := httptest.NewRequest(http.MethodGet, "/admin/overview", nil)
	req = req.WithContext(WithUser(req.Context(), "admin-1", "user"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !called {
		t.Fatalf("expected admin to pass through; code=%d called=%v", rr.Code, called)
	}
}

func TestRequireSuperAdminBlocksOnError(t *testing.T) {
	mw := RequireSuperAdmin(func(ctx context.Context, userID string) (bool, error) {
		return false, context.DeadlineExceeded
	})
	rr := httptest.NewRecorder()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/admin/overview", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a checker error must fail closed (403), got %d", rr.Code)
	}
}
