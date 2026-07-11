package services

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/models"
)

// serviceProvider builds a crewjam SAML SP for a connection. We only validate
// IdP-signed assertions (no SP signing / no assertion encryption), so no SP
// keypair is required.
func (s *SSOService) serviceProvider(conn *models.SSOConnection) (*saml.ServiceProvider, error) {
	if conn.SAMLIdPSSOURL == nil || conn.SAMLIdPCertificate == nil || conn.SAMLIdPEntityID == nil {
		return nil, ErrSSONotConfigured
	}
	block, _ := pem.Decode([]byte(*conn.SAMLIdPCertificate))
	if block == nil {
		return nil, errors.New("invalid IdP certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse IdP certificate: %w", err)
	}
	acs, _ := url.Parse(s.baseURL + "/api/v1/auth/sso/saml/acs")
	meta, _ := url.Parse(s.baseURL + "/api/v1/auth/sso/" + conn.ID + "/saml/metadata")
	sp := &saml.ServiceProvider{
		EntityID:    meta.String(),
		AcsURL:      *acs,
		MetadataURL: *meta,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: *conn.SAMLIdPEntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{{
							Use: "signing",
							KeyInfo: saml.KeyInfo{
								X509Data: saml.X509Data{
									X509Certificates: []saml.X509Certificate{{
										Data: certToB64(cert),
									}},
								},
							},
						}},
					},
				},
				SingleSignOnServices: []saml.Endpoint{{
					Binding:  saml.HTTPRedirectBinding,
					Location: *conn.SAMLIdPSSOURL,
				}},
			}},
		},
	}
	return sp, nil
}

// SAMLMetadata returns the SP metadata XML the customer registers with their IdP.
func (s *SSOService) SAMLMetadata(ctx context.Context, connID string) ([]byte, error) {
	conn, err := s.repo.GetConnection(ctx, connID)
	if err != nil {
		return nil, err
	}
	sp, err := s.serviceProvider(conn)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

// StartSAML builds the SP-initiated AuthnRequest redirect and stashes its ID so
// the ACS can bind the response to this request (replay/injection protection).
func (s *SSOService) StartSAML(ctx context.Context, conn *models.SSOConnection) (string, error) {
	sp, err := s.serviceProvider(conn)
	if err != nil {
		return "", err
	}
	req, err := sp.MakeAuthenticationRequest(*conn.SAMLIdPSSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", err
	}
	relay := randToken()
	if err := s.rdb.Set(ctx, "aegis:sso:saml:"+relay, conn.ID+"|"+req.ID, 10*time.Minute).Err(); err != nil {
		return "", err
	}
	u, err := req.Redirect(relay, sp)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// CompleteSAML validates the ACS POST, provisions the user, and issues tokens.
func (s *SSOService) CompleteSAML(ctx context.Context, r *http.Request) (*models.User, *auth.TokenPair, error) {
	if err := r.ParseForm(); err != nil {
		return nil, nil, err
	}
	relay := r.Form.Get("RelayState")
	stored, err := s.rdb.GetDel(ctx, "aegis:sso:saml:"+relay).Result()
	if err != nil {
		return nil, nil, ErrSSOState
	}
	connID, reqID, ok := strings.Cut(stored, "|")
	if !ok {
		return nil, nil, ErrSSOState
	}
	conn, err := s.repo.GetConnection(ctx, connID)
	if err != nil {
		return nil, nil, err
	}
	sp, err := s.serviceProvider(conn)
	if err != nil {
		return nil, nil, err
	}
	assertion, err := sp.ParseResponse(r, []string{reqID})
	if err != nil {
		return nil, nil, fmt.Errorf("validate saml response: %w", err)
	}
	email, name, nameID := samlAttributes(assertion, conn)
	external := nameID
	if external == "" {
		external = email
	}
	return s.provision(ctx, conn, external, email, name)
}

// samlAttributes extracts email/name/NameID from a validated assertion.
func samlAttributes(a *saml.Assertion, conn *models.SSOConnection) (email, name, nameID string) {
	if a.Subject != nil && a.Subject.NameID != nil {
		nameID = a.Subject.NameID.Value
	}
	emailKeys := []string{conn.AttrEmail, "email", "mail",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}
	nameKeys := []string{conn.AttrName, "name", "displayName",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			var val string
			if len(attr.Values) > 0 {
				val = attr.Values[0].Value
			}
			if val == "" {
				continue
			}
			if email == "" && matchesAny(attr, emailKeys) {
				email = val
			}
			if name == "" && matchesAny(attr, nameKeys) {
				name = val
			}
		}
	}
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}
	return email, name, nameID
}

func matchesAny(attr saml.Attribute, keys []string) bool {
	for _, k := range keys {
		if k != "" && (strings.EqualFold(attr.Name, k) || strings.EqualFold(attr.FriendlyName, k)) {
			return true
		}
	}
	return false
}

func certToB64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
