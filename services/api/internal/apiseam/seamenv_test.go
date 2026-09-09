package apiseam

import (
	"os"
	"testing"
)

// requireSeamEnv returns the seam environment, or ends the test.
//
// K1: skipping locally is fine; skipping in CI is the bug. Two identical P0s
// shipped through green pipelines — T2's excluded_bundled and J4's code_key —
// both of which broke every scan-read endpoint via SELECT * into a struct
// missing the column. The tests that catch that already existed. They skipped,
// because nothing set these variables and no CI job stood up a database.
//
// So: in CI, an absent seam environment is a hard failure. A guard that quietly
// declines to run is indistinguishable from one that passes, and this repository
// has now been bitten by that twice.
func requireSeamEnv(t *testing.T, needAPI bool) (apiURL, dbURL string) {
	t.Helper()
	apiURL, dbURL = os.Getenv("AEGIS_SEAM_API_URL"), os.Getenv("AEGIS_SEAM_DB_URL")

	missing := dbURL == "" || (needAPI && apiURL == "")
	if !missing {
		return apiURL, dbURL
	}

	// GitHub Actions and most CI systems set CI=true.
	if os.Getenv("CI") != "" {
		t.Fatalf("seam environment is not configured in CI.\n\n"+
			"AEGIS_SEAM_DB_URL=%q AEGIS_SEAM_API_URL=%q\n\n"+
			"These seams exist to catch schema/struct drift that unit tests, `go build` "+
			"and `go vet` all miss. Letting them skip in CI is how that class shipped "+
			"twice. Stand up the stack in the workflow, or delete the test — do not "+
			"leave it silently inert.", dbURL, apiURL)
	}
	t.Skip("set AEGIS_SEAM_DB_URL (and AEGIS_SEAM_API_URL) to run the API seams locally")
	return "", ""
}
