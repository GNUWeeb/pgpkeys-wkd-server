// Package export writes the stored keys into a directory laid out like
// kernel.org's pgpkeys.git, so that "gpg --import keys/*.asc" imports the
// keyring.
package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
)

// The two directories of the layout, relative to the export directory:
// keys whose primary key has expired go to Expired, the others to Live.
// Revoked keys stay in Live, so that importing the keyring brings their
// revocations along.
const (
	Live    = "keys"
	Expired = "keys/expired"
)

// keyFile matches the files the export owns: a fingerprint, as Parse
// writes it, with the .asc suffix. Other files are left alone.
var keyFile = regexp.MustCompile(`^(?:[0-9A-F]{40}|[0-9A-F]{64})\.asc$`)

// Result lists what Write changed, as paths relative to the export
// directory, sorted.
type Result struct {
	Written []string
	Removed []string
}

// Write brings dir up to date with the store at the time now: every
// stored key as one armored file named after its fingerprint, with all of
// its User IDs and certifications as uploaded. A key stored for several
// addresses is written once, from its latest upload. Files whose content
// is already right are not touched, so an unchanged store leaves dir as it
// was; key files of keys no longer stored are removed.
func Write(ctx context.Context, st *store.Store, dir string, now time.Time) (Result, error) {
	all, err := st.AllKeys(ctx)
	if err != nil {
		return Result{}, err
	}
	latest := map[string]store.StoredKey{}
	for _, k := range all {
		if prev, ok := latest[k.Fingerprint]; !ok || k.Uploaded.After(prev.Uploaded) || (k.Uploaded.Equal(prev.Uploaded) && k.ID > prev.ID) {
			latest[k.Fingerprint] = k
		}
	}

	want := map[string][]byte{}
	for fpr, k := range latest {
		info, err := keys.Describe(k.Data, now)
		if err != nil {
			return Result{}, fmt.Errorf("key %s: %w", fpr, err)
		}
		sub := Live
		if info.Expired && !info.Revoked {
			sub = Expired
		}
		b, err := armored(k.Data)
		if err != nil {
			return Result{}, err
		}
		want[filepath.Join(sub, fpr+".asc")] = b
	}

	var res Result
	for _, sub := range []string{Live, Expired} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return Result{}, err
		}
	}
	for rel, b := range want {
		path := filepath.Join(dir, rel)
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
			continue
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Result{}, err
		}
		if err := writeFile(path, b); err != nil {
			return Result{}, err
		}
		res.Written = append(res.Written, rel)
	}
	for _, sub := range []string{Live, Expired} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			return Result{}, err
		}
		for _, e := range entries {
			rel := filepath.Join(sub, e.Name())
			if !e.Type().IsRegular() || !keyFile.MatchString(e.Name()) || want[rel] != nil {
				continue
			}
			if err := os.Remove(filepath.Join(dir, rel)); err != nil {
				return Result{}, err
			}
			res.Removed = append(res.Removed, rel)
		}
	}
	slices.Sort(res.Written)
	slices.Sort(res.Removed)
	return res, nil
}

func armored(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// writeFile replaces path with b in one step, so a reader never sees half
// a key.
func writeFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".export-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
