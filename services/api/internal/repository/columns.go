package repository

import (
	"reflect"
	"strings"
)

// columnsOf builds an explicit SELECT column list from a struct's `db:` tags.
//
// Why explicit lists at all (K2). `SELECT *` makes an additive migration
// backward-INCOMPATIBLE: sqlx fails with "missing destination name <col>" the
// moment a column exists that the running binary's struct does not declare. That
// shipped twice as a P0 — T2's excluded_bundled and J4's code_key — each time
// breaking every scan-read endpoint.
//
// An explicit list inverts that. The query asks for the columns this binary
// knows about, so a column added by a migration is simply not selected and the
// old binary keeps working. Combined with migrate-first — which both deploy
// paths already enforce (docs/DEPLOY_ORDERING.md) — a rolling upgrade is safe:
// the migration lands, old pods ignore the new column, new pods use it.
//
// The list is DERIVED, never hand-written. A hand-maintained list that goes
// stale is the same defect wearing different clothes: repository/scan.go's
// scanColumns had to be edited by hand every time the model changed, and nothing
// checked that it still matched. Generating from the tags removes the class.
//
// alias, when non-empty, qualifies every column (e.g. "s" -> "s.id, s.status").
// Postgres strips the qualifier from result column names, so sqlx still maps
// them onto the struct.
//
// Fields tagged `db:"-"` are skipped. Embedded structs are walked so a model
// composed of parts still yields a flat column list.
func columnsOf(v any, alias string) string {
	cols := dbTagsOf(v)
	if alias != "" {
		for i, c := range cols {
			cols[i] = alias + "." + c
		}
	}
	return strings.Join(cols, ", ")
}

// dbTagsOf returns the `db:` tag names of a struct, in declaration order.
func dbTagsOf(v any) []string {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			out = append(out, dbTagsOf(reflect.New(f.Type).Elem().Interface())...)
			continue
		}
		tag := f.Tag.Get("db")
		if tag == "" || tag == "-" {
			continue
		}
		// `db:"name,omitempty"` -> name
		if i := strings.IndexByte(tag, ','); i >= 0 {
			tag = tag[:i]
		}
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}
