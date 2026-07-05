package notify

import (
	"fmt"
	"strings"

	"github.com/aegis-platform/api/internal/models"
)

// severityCounts tallies non-suppressed findings by severity.
func severityCounts(findings []models.Finding) map[string]int {
	c := map[string]int{}
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		c[f.Severity]++
	}
	return c
}

func gradeOf(scan *models.Scan) string {
	if scan.OverallGrade != nil && *scan.OverallGrade != "" {
		return *scan.OverallGrade
	}
	return "—"
}

// ScanCompleteEmail summarizes a finished scan.
func ScanCompleteEmail(to, dashURL, project string, scan *models.Scan, findings []models.Finding) Email {
	c := severityCounts(findings)
	subject := fmt.Sprintf("[Aegis] %s scan complete — grade %s", project, gradeOf(scan))
	text := fmt.Sprintf("Scan of %s complete. Grade %s.\nFindings — critical: %d, high: %d, medium: %d, low: %d.\n\n%s",
		project, gradeOf(scan), c["critical"], c["high"], c["medium"], c["low"], dashURL)
	html := fmt.Sprintf(
		"<h2>%s scan complete</h2><p>Grade <b>%s</b></p>"+
			"<p>Critical: <b>%d</b> · High: <b>%d</b> · Medium: %d · Low: %d</p>"+
			"<p><a href=\"%s\">View the full report</a></p>",
		project, gradeOf(scan), c["critical"], c["high"], c["medium"], c["low"], dashURL)
	return Email{To: to, Subject: subject, Text: text, HTML: html}
}

// NewCriticalEmail alerts on newly-introduced critical findings.
func NewCriticalEmail(to, dashURL, project string, scan *models.Scan, newCriticals []models.Finding) Email {
	subject := fmt.Sprintf("[Aegis] 🚨 %d new critical finding(s) in %s", len(newCriticals), project)
	var b strings.Builder
	fmt.Fprintf(&b, "%d new critical finding(s) appeared in %s:\n\n", len(newCriticals), project)
	for i, f := range newCriticals {
		if i >= 10 {
			break
		}
		title := f.Title
		if f.TitleHuman != nil && *f.TitleHuman != "" {
			title = *f.TitleHuman
		}
		fmt.Fprintf(&b, "- %s (%s)\n", title, f.FilePath)
	}
	fmt.Fprintf(&b, "\n%s", dashURL)
	html := "<h2>🚨 New critical findings in " + project + "</h2><pre>" + b.String() + "</pre>" +
		fmt.Sprintf("<p><a href=\"%s\">Review in Aegis</a></p>", dashURL)
	return Email{To: to, Subject: subject, Text: b.String(), HTML: html}
}

// InvitationEmail invites a teammate to an organization.
func InvitationEmail(to, dashURL, orgName, inviter, token string) Email {
	acceptURL := strings.TrimSuffix(dashURL, "/") + "/invitations/accept?token=" + token
	subject := fmt.Sprintf("[Aegis] You're invited to join %s", orgName)
	text := fmt.Sprintf("%s invited you to join %s on Aegis.\nAccept: %s", inviter, orgName, acceptURL)
	html := fmt.Sprintf("<h2>Join %s on Aegis</h2><p>%s invited you.</p><p><a href=\"%s\">Accept the invitation</a></p>",
		orgName, inviter, acceptURL)
	return Email{To: to, Subject: subject, Text: text, HTML: html}
}

// SlackScanMessage renders a scan summary as a Slack Block Kit message.
func SlackScanMessage(dashURL, project string, scan *models.Scan, findings []models.Finding) SlackMessage {
	c := severityCounts(findings)
	header := fmt.Sprintf("*%s* scan complete — grade *%s*", project, gradeOf(scan))
	summary := fmt.Sprintf("🔴 %d critical · 🟠 %d high · 🟡 %d medium · %d low",
		c["critical"], c["high"], c["medium"], c["low"])
	return SlackMessage{
		Text: header + "\n" + summary,
		Blocks: []map[string]any{
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": header}},
			{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": summary}},
			{"type": "actions", "elements": []map[string]any{
				{"type": "button", "text": map[string]any{"type": "plain_text", "text": "View in Aegis"}, "url": dashURL},
			}},
		},
	}
}
