package wkd

import "testing"

func TestHash(t *testing.T) {
	for local, want := range map[string]string{
		"Joe.Doe":  "iy9q119eutrkn8s1mk4r39qejnbu3n5q", // the draft's test vector
		"joe.doe":  "iy9q119eutrkn8s1mk4r39qejnbu3n5q",
		"torvalds": "pf113mfnx1f3eb1yiwhsipa91xfc7o4x", // served by kernel.org
		"gregkh":   "e3n9xnm94c5apezqnj1pmrfuaoyfm8cf", // served by kernel.org
	} {
		if got := Hash(local); got != want {
			t.Errorf("Hash(%q) = %s, want %s", local, got, want)
		}
	}
}

func TestHashLowercasesOnlyASCII(t *testing.T) {
	if Hash("ÄBC") == Hash("äbc") {
		t.Error("non-ASCII letters were case-folded")
	}
	if Hash("ÄBC") != Hash("Äbc") {
		t.Error("ASCII letters next to non-ASCII ones were not lower-cased")
	}
}

func TestValidHash(t *testing.T) {
	for s, want := range map[string]bool{
		"iy9q119eutrkn8s1mk4r39qejnbu3n5q":  true,
		"iy9q119eutrkn8s1mk4r39qejnbu3n5":   false, // short
		"iy9q119eutrkn8s1mk4r39qejnbu3n5qq": false, // long
		"IY9Q119EUTRKN8S1MK4R39QEJNBU3N5Q":  false, // upper case
		"iy9q119eutrkn8s1mk4r39qejnbu3n50":  false, // '0' is not in the alphabet
		"iy9q119eutrkn8s1mk4r39qejnbu3n5l":  false, // nor is 'l'
	} {
		if got := ValidHash(s); got != want {
			t.Errorf("ValidHash(%q) = %v, want %v", s, got, want)
		}
	}
}
