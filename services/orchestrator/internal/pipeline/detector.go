package pipeline

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Detection is the result of inspecting a checked-out repository.
type Detection struct {
	PrimaryLanguage string
	Languages       []string
	ProjectTypes    []string
}

// markerFiles maps a marker filename to (projectType, language).
var markerFiles = map[string][2]string{
	"package.json":     {"node", "javascript"},
	"tsconfig.json":    {"node", "typescript"},
	"go.mod":           {"go", "go"},
	"requirements.txt": {"python", "python"},
	"pyproject.toml":   {"python", "python"},
	"Pipfile":          {"python", "python"},
	"pom.xml":          {"maven", "java"},
	"build.gradle":     {"gradle", "java"},
	"Gemfile":          {"ruby", "ruby"},
	"Cargo.toml":       {"cargo", "rust"},
	"composer.json":    {"php", "php"},
}

// extensionLanguages maps file extensions to canonical language names.
var extensionLanguages = map[string]string{
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".tsx": "typescript",
	".py": "python", ".go": "go", ".java": "java", ".rb": "ruby",
	".rs": "rust", ".php": "php", ".cs": "csharp",
}

// ignoredDirs are skipped during detection.
var ignoredDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "out": true, ".next": true, "__pycache__": true,
	".venv": true, "venv": true, "target": true,
}

// Detect walks the tree once, classifying languages and project types. Bounded
// by maxFiles so a hostile repo cannot stall the worker.
func Detect(root string) Detection {
	const maxFiles = 50000

	extCounts := map[string]int{}
	markerLangCounts := map[string]int{}
	typeSet := map[string]bool{}
	scanned := 0

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		scanned++
		if scanned > maxFiles {
			return filepath.SkipAll
		}
		name := d.Name()
		if m, ok := markerFiles[name]; ok {
			typeSet[m[0]] = true
			markerLangCounts[m[1]]++
		}
		if lang, ok := extensionLanguages[strings.ToLower(filepath.Ext(name))]; ok {
			extCounts[lang]++
		}
		return nil
	})

	languages := sortByCount(extCounts)
	primary := ""
	if len(languages) > 0 {
		primary = languages[0]
	} else if len(markerLangCounts) > 0 {
		primary = sortByCount(markerLangCounts)[0]
	}

	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)

	return Detection{PrimaryLanguage: primary, Languages: languages, ProjectTypes: types}
}

// sortByCount returns keys ordered by descending count (ties broken by name).
func sortByCount(counts map[string]int) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}
