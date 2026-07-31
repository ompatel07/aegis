package services

import "github.com/aegis-platform/api/internal/models"

// ensureWriteRole gates a state-changing action on a minimum org role of
// "member" (i.e. excludes read-only viewers). It is designed to consume a repo
// role-lookup's (role, error) return directly:
//
//	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, id, userID)); err != nil {
//	    return err
//	}
//
// A lookup error is returned unchanged: RoleIn*Org returns ErrNotFound (→ 404)
// for a non-member or a missing resource, which preserves cross-tenant isolation
// (a non-member cannot distinguish a foreign resource from a nonexistent one). A
// member whose role is below "member" (a viewer) gets ErrForbidden (→ 403).
func ensureWriteRole(role string, lookupErr error) error {
	if lookupErr != nil {
		return lookupErr
	}
	if !models.RoleAtLeast(role, models.OrgRoleMember) {
		return ErrForbidden
	}
	return nil
}
