package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

var (
	// ErrForbidden is returned when a member lacks the required role.
	ErrForbidden = errors.New("insufficient role for this action")
	// ErrInvitationInvalid covers expired / already-accepted / unknown tokens.
	ErrInvitationInvalid = errors.New("invitation is invalid or expired")
	// ErrLastOwner prevents removing/demoting an org's only owner.
	ErrLastOwner = errors.New("cannot remove the last owner of an organization")
)

// OrganizationService implements org + membership + invitation logic with
// role-based authorization.
type OrganizationService struct {
	orgs  *repository.OrganizationRepository
	users *repository.UserRepository
}

func NewOrganizationService(orgs *repository.OrganizationRepository, users *repository.UserRepository) *OrganizationService {
	return &OrganizationService{orgs: orgs, users: users}
}

// requireRole loads the actor's role and enforces a minimum privilege level.
func (s *OrganizationService) requireRole(ctx context.Context, orgID, userID, minRole string) (string, error) {
	role, err := s.orgs.RoleOf(ctx, orgID, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", repository.ErrNotFound // not a member → 404, don't leak existence
		}
		return "", err
	}
	if !models.RoleAtLeast(role, minRole) {
		return role, ErrForbidden
	}
	return role, nil
}

func (s *OrganizationService) List(ctx context.Context, userID string) ([]models.OrgMembership, error) {
	return s.orgs.ListForUser(ctx, userID)
}

func (s *OrganizationService) Create(ctx context.Context, userID, name string, billingEmail *string) (*models.Organization, error) {
	o := &models.Organization{
		Name:         name,
		Slug:         slugify(name),
		BillingEmail: billingEmail,
		Plan:         models.PlanFree,
	}
	if err := s.orgs.Create(ctx, o, userID); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *OrganizationService) Get(ctx context.Context, orgID, userID string) (*models.Organization, error) {
	return s.orgs.GetForUser(ctx, orgID, userID)
}

func (s *OrganizationService) UpdateSettings(ctx context.Context, orgID, userID, name string, billingEmail *string) (*models.Organization, error) {
	if _, err := s.requireRole(ctx, orgID, userID, models.OrgRoleAdmin); err != nil {
		return nil, err
	}
	if err := s.orgs.UpdateSettings(ctx, orgID, name, billingEmail); err != nil {
		return nil, err
	}
	return s.orgs.GetForUser(ctx, orgID, userID)
}

func (s *OrganizationService) Members(ctx context.Context, orgID, userID string) ([]models.OrgMember, error) {
	if _, err := s.requireRole(ctx, orgID, userID, models.OrgRoleViewer); err != nil {
		return nil, err
	}
	return s.orgs.Members(ctx, orgID)
}

// Invite creates a pending invitation (admin+). If the invited email already
// belongs to a user, they are added immediately; otherwise a token is minted
// (delivered by email in TASK 7; also returned so the flow works offline).
func (s *OrganizationService) Invite(ctx context.Context, orgID, actorID, email, role string) (*models.OrgInvitation, bool, error) {
	if _, err := s.requireRole(ctx, orgID, actorID, models.OrgRoleAdmin); err != nil {
		return nil, false, err
	}
	if _, ok := map[string]bool{models.OrgRoleAdmin: true, models.OrgRoleMember: true, models.OrgRoleViewer: true, models.OrgRoleOwner: true}[role]; !ok {
		role = models.OrgRoleMember
	}

	// Existing user → add directly.
	if u, err := s.users.GetByEmail(ctx, email); err == nil {
		if err := s.orgs.AddMember(ctx, orgID, u.ID, role, actorID); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, false, err
	}

	inv := &models.OrgInvitation{
		OrgID:     orgID,
		Email:     strings.ToLower(email),
		Role:      role,
		Token:     randomToken(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if err := s.orgs.CreateInvitation(ctx, inv, actorID); err != nil {
		return nil, false, err
	}
	return inv, false, nil
}

func (s *OrganizationService) ListInvitations(ctx context.Context, orgID, userID string) ([]models.OrgInvitation, error) {
	if _, err := s.requireRole(ctx, orgID, userID, models.OrgRoleAdmin); err != nil {
		return nil, err
	}
	return s.orgs.ListInvitations(ctx, orgID)
}

func (s *OrganizationService) RevokeInvitation(ctx context.Context, orgID, userID, invID string) error {
	if _, err := s.requireRole(ctx, orgID, userID, models.OrgRoleAdmin); err != nil {
		return err
	}
	return s.orgs.DeleteInvitation(ctx, orgID, invID)
}

// Accept joins the current user to the org named by an invitation token.
func (s *OrganizationService) Accept(ctx context.Context, userID, token string) (*models.Organization, error) {
	inv, err := s.orgs.InvitationByToken(ctx, token)
	if err != nil {
		return nil, ErrInvitationInvalid
	}
	if inv.AcceptedAt != nil || time.Now().After(inv.ExpiresAt) {
		return nil, ErrInvitationInvalid
	}
	// Bind the invite to the accepting user's email to stop token forwarding.
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Email, inv.Email) {
		return nil, ErrForbidden
	}
	if err := s.orgs.AddMember(ctx, inv.OrgID, userID, inv.Role, ""); err != nil {
		return nil, err
	}
	_ = s.orgs.MarkInvitationAccepted(ctx, inv.ID)
	return s.orgs.GetForUser(ctx, inv.OrgID, userID)
}

func (s *OrganizationService) SetMemberRole(ctx context.Context, orgID, actorID, targetID, role string) error {
	if _, err := s.requireRole(ctx, orgID, actorID, models.OrgRoleAdmin); err != nil {
		return err
	}
	// Prevent demoting the last owner.
	if role != models.OrgRoleOwner {
		if cur, _ := s.orgs.RoleOf(ctx, orgID, targetID); cur == models.OrgRoleOwner {
			if n, _ := s.orgs.CountOwners(ctx, orgID); n <= 1 {
				return ErrLastOwner
			}
		}
	}
	return s.orgs.SetRole(ctx, orgID, targetID, role)
}

func (s *OrganizationService) RemoveMember(ctx context.Context, orgID, actorID, targetID string) error {
	// A user may always remove themselves (leave); otherwise admin+ required.
	if actorID != targetID {
		if _, err := s.requireRole(ctx, orgID, actorID, models.OrgRoleAdmin); err != nil {
			return err
		}
	}
	if cur, _ := s.orgs.RoleOf(ctx, orgID, targetID); cur == models.OrgRoleOwner {
		if n, _ := s.orgs.CountOwners(ctx, orgID); n <= 1 {
			return ErrLastOwner
		}
	}
	return s.orgs.RemoveMember(ctx, orgID, targetID)
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
