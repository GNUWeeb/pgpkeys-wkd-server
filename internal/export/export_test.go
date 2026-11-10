package export

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
)

var created = time.Unix(1_800_000_000, 0)

const day = 24 * time.Hour

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// put stores a new key for address that lives for lifetime (0: forever)
// and returns it as stored.
func put(t *testing.T, st *store.Store, address string, lifetime time.Duration) *keys.Key {
	t.Helper()
	cfg := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: uint32(lifetime / time.Second),
		Time:            func() time.Time { return created },
	}
	e, err := openpgp.NewEntity("Test", "", address, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	k, err := keys.Parse(b.Bytes(), address, created)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKey(context.Background(), address, k, created); err != nil {
		t.Fatal(err)
	}
	return k
}

// readKey dearmors the exported file rel in dir.
func readKey(t *testing.T, dir, rel string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(block.Body); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestWrite(t *testing.T) {
	st := newStore(t)
	dir := t.TempDir()
	alice := put(t, st, "alice@gnuweeb.org", 0)
	bob := put(t, st, "bob@gnuweeb.org", 30*day)
	// A file the export does not own stays.
	if err := os.MkdirAll(filepath.Join(dir, Live), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, Live, "README"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	res, err := Write(ctx, st, dir, created.Add(day))
	if err != nil {
		t.Fatal(err)
	}
	aliceFile, bobFile := filepath.Join(Live, alice.Fingerprint+".asc"), filepath.Join(Live, bob.Fingerprint+".asc")
	if want := []string{aliceFile, bobFile}; !sameSet(res.Written, want) || len(res.Removed) != 0 {
		t.Fatalf("first run: %+v, want %v written", res, want)
	}
	if got := readKey(t, dir, aliceFile); !bytes.Equal(got, alice.Data) {
		t.Error("exported key differs from the stored one")
	}
	before, _ := os.ReadFile(filepath.Join(dir, aliceFile))

	// Nothing changed: nothing written, the same bytes.
	res, err = Write(ctx, st, dir, created.Add(2*day))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written)+len(res.Removed) != 0 {
		t.Errorf("unchanged store: %+v", res)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, aliceFile)); !bytes.Equal(before, after) {
		t.Error("unchanged store gave different bytes")
	}

	// Bob's key expires: it moves to keys/expired/.
	res, err = Write(ctx, st, dir, created.Add(31*day))
	if err != nil {
		t.Fatal(err)
	}
	expiredFile := filepath.Join(Expired, bob.Fingerprint+".asc")
	if !slices.Equal(res.Written, []string{expiredFile}) || !slices.Equal(res.Removed, []string{bobFile}) {
		t.Errorf("after expiry: %+v, want %s moved to %s", res, bobFile, expiredFile)
	}

	// Alice removes her key: its file goes, README stays.
	if _, err := st.DeleteKey(ctx, "alice@gnuweeb.org", alice.Fingerprint); err != nil {
		t.Fatal(err)
	}
	res, err = Write(ctx, st, dir, created.Add(31*day))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Removed, []string{aliceFile}) || len(res.Written) != 0 {
		t.Errorf("after removal: %+v, want %s removed", res, aliceFile)
	}
	if _, err := os.Stat(filepath.Join(dir, Live, "README")); err != nil {
		t.Errorf("README: %v", err)
	}
}

func TestWriteOneFilePerKey(t *testing.T) {
	st := newStore(t)
	k := put(t, st, "alice@gnuweeb.org", 0)
	// The same key under an alias, uploaded later.
	if err := st.PutKey(context.Background(), "alias@gnuweeb.org", k, created.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err := Write(context.Background(), st, t.TempDir(), created.Add(day))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Written) != 1 {
		t.Errorf("wrote %v, want one file", res.Written)
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
