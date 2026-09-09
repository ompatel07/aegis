package repository

import (
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

// The column list must be derived, never transcribed. These tests pin the
// derivation itself; the seam test in internal/apiseam checks the result against
// a live schema.

func TestColumnsOfDerivesFromDBTags(t *testing.T) {
	type inner struct {
		A string `db:"a"`
	}
	type sample struct {
		inner
		B  string  `db:"b"`
		C  *string `db:"c,omitempty"`
		Skip string `db:"-"`
		NoTag string
	}
	got := columnsOf(sample{}, "")
	want := "a, b, c"
	if got != want {
		t.Fatalf("columnsOf = %q, want %q", got, want)
	}
}

func TestColumnsOfQualifiesWithAnAlias(t *testing.T) {
	type sample struct {
		ID string `db:"id"`
		N  int    `db:"n"`
	}
	if got, want := columnsOf(sample{}, "s"), "s.id, s.n"; got != want {
		t.Fatalf("columnsOf = %q, want %q", got, want)
	}
}

// FindingColumns is what the repository actually queries with. If it ever stops
// covering the model, the SELECT silently returns fewer fields than the struct
// expects and callers see zero values instead of data — quieter than the SELECT *
// failure it replaced, and worse for it.
func TestFindingColumnsCoverEveryModelField(t *testing.T) {
	tags := dbTagsOf(models.Finding{})
	if len(tags) == 0 {
		t.Fatal("models.Finding has no db tags")
	}
	cols := strings.Split(FindingColumns, ", ")
	if len(cols) != len(tags) {
		t.Fatalf("FindingColumns has %d columns, models.Finding has %d db tags", len(cols), len(tags))
	}
	have := make(map[string]bool, len(cols))
	for _, c := range cols {
		have[c] = true
	}
	for _, tag := range tags {
		if !have[tag] {
			t.Errorf("FindingColumns is missing %q", tag)
		}
	}
}

// Every derived list must cover its whole model. Table-driven so a newly
// converted table is one line, and forgetting the check is visible.
func TestDerivedColumnListsCoverTheirModels(t *testing.T) {
	cases := []struct {
		name string
		list string
		tags []string
	}{
		{"findings", FindingColumns, dbTagsOf(models.Finding{})},
		{"projects", ProjectColumns, dbTagsOf(models.Project{})},
		{"users", UserColumns, dbTagsOf(models.User{})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.tags) == 0 {
				t.Fatalf("%s model has no db tags", c.name)
			}
			cols := strings.Split(c.list, ", ")
			if len(cols) != len(c.tags) {
				t.Fatalf("%s: list has %d columns, model has %d db tags", c.name, len(cols), len(c.tags))
			}
			have := make(map[string]bool, len(cols))
			for _, col := range cols {
				have[col] = true
			}
			for _, tag := range c.tags {
				if !have[tag] {
					t.Errorf("%s: list is missing %q", c.name, tag)
				}
			}
			if strings.Contains(c.list, "*") {
				t.Errorf("%s: list contains *, which is what K2 removed", c.name)
			}
		})
	}
}

func TestFindingColumnsAreNotSelectStar(t *testing.T) {
	if strings.Contains(FindingColumns, "*") {
		t.Fatal("FindingColumns must be an explicit list; SELECT * is what K2 removed")
	}
	// The two columns whose absence from the struct caused a P0.
	for _, c := range []string{"code_key", "fingerprint"} {
		if !strings.Contains(FindingColumns, c) {
			t.Errorf("FindingColumns does not include %q", c)
		}
	}
}
