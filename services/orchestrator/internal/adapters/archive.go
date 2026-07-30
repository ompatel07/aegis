package adapters

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Decompression-bomb + zip-slip guards for uploaded code archives (Method B).
const (
	maxUncompressedBytes int64 = 1024 * 1024 * 1024 // 1 GiB total extracted
	maxArchiveEntries          = 100_000            // file-count ceiling
	maxSingleFileBytes   int64 = 200 * 1024 * 1024  // 200 MiB per file
)

// ExtractArchive safely extracts a .zip or .tar.gz code archive into destDir.
// It defends against decompression bombs (caps total bytes, per-file bytes, and
// entry count), zip-slip / path traversal (every entry must resolve inside
// destDir), and symlink escapes (symlinks are skipped). Returns the number of
// files written.
func ExtractArchive(archivePath, destDir string) (int, error) {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return 0, fmt.Errorf("create dest: %w", err)
	}
	lower := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractZip(archivePath, destDir)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return extractTarGz(archivePath, destDir)
	default:
		return 0, fmt.Errorf("unsupported archive type (expected .zip or .tar.gz)")
	}
}

// safeJoin resolves name under destDir, rejecting absolute paths and any `..`
// escape (zip-slip). Returns the cleaned absolute target path.
func safeJoin(destDir, name string) (string, error) {
	if strings.Contains(name, "\x00") {
		return "", fmt.Errorf("illegal null byte in entry name")
	}
	target := filepath.Join(destDir, name)
	// destDir + separator guards against a prefix match like /dest vs /destEVIL.
	if target != destDir && !strings.HasPrefix(target, destDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal in archive entry: %q", name)
	}
	return target, nil
}

func extractZip(archivePath, destDir string) (int, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	var total int64
	written := 0
	for _, f := range zr.File {
		if written >= maxArchiveEntries {
			return written, fmt.Errorf("archive exceeds entry limit (%d)", maxArchiveEntries)
		}
		// Skip symlinks and irregular files (mode bits from the zip header).
		if f.Mode()&os.ModeSymlink != 0 {
			continue
		}
		target, err := safeJoin(destDir, f.Name)
		if err != nil {
			return written, err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return written, err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return written, err
		}
		n, werr := writeCapped(rc, target, &total)
		rc.Close()
		if werr != nil {
			return written, werr
		}
		if n > 0 {
			written++
		}
	}
	return written, nil
}

func extractTarGz(archivePath, destDir string) (int, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return 0, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	var total int64
	written := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, fmt.Errorf("tar: %w", err)
		}
		if written >= maxArchiveEntries {
			return written, fmt.Errorf("archive exceeds entry limit (%d)", maxArchiveEntries)
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return written, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return written, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
				return written, err
			}
			if _, werr := writeCapped(tr, target, &total); werr != nil {
				return written, werr
			}
			written++
		default:
			// Skip symlinks, hardlinks, devices, fifos — never materialise them.
			continue
		}
	}
	return written, nil
}

// writeCapped copies src to a new file at target, enforcing per-file and running
// total byte caps so a decompression bomb can't fill the disk.
func writeCapped(src io.Reader, target string, total *int64) (int64, error) {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	buf := make([]byte, 32*1024)
	var fileBytes int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			fileBytes += int64(n)
			*total += int64(n)
			if fileBytes > maxSingleFileBytes {
				return fileBytes, fmt.Errorf("archive entry exceeds per-file limit (decompression bomb?)")
			}
			if *total > maxUncompressedBytes {
				return fileBytes, fmt.Errorf("archive exceeds total size limit (decompression bomb?)")
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				return fileBytes, werr
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fileBytes, rerr
		}
	}
	return fileBytes, nil
}
