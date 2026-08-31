package pipeline

import "testing"

// The deployment engine is the ONLY engine that can run a build/install subprocess
// (npm ci / mvn package / …) on customer code. Aegis is a two-pillar product on the
// web/API path; a web-initiated scan (ciMode=false) must be structurally unable to
// reach the deployment engine. If someone re-adds the deployment call to the default
// engine set, this test fails.
func TestWebScanNeverInvokesDeployment(t *testing.T) {
	p := &Pipeline{}

	for _, c := range p.engineCalls("dir", "s1", nil, nil, nil, false /* ciMode */) {
		if c.engine == "deployment" {
			t.Fatal("web scan (ciMode=false) includes the deployment engine — the " +
				"no-build boundary is breached; deployment must be CI-mode only")
		}
	}

	// CI mode DOES offer it (inspection-only; the scanner never builds).
	hasDeploy := false
	for _, c := range p.engineCalls("dir", "s1", nil, nil, nil, true /* ciMode */) {
		if c.engine == "deployment" {
			hasDeploy = true
		}
	}
	if !hasDeploy {
		t.Fatal("CI mode should offer the deployment engine (inspection-only)")
	}
}
