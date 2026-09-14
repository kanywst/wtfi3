package oui

import "testing"

func TestLookup(t *testing.T) {
	if got := Lookup("b8:27:eb:11:22:33"); len(got) < 9 || got[:9] != "Raspberry" {
		t.Fatalf("Lookup(rpi) = %q", got)
	}
	if got := Lookup("00:00:00:00:00:01"); got != "Xerox" {
		t.Fatalf("Lookup(xerox) = %q", got)
	}
	if got := Lookup("06:11:22:33:44:55"); got != "randomized?" {
		t.Fatalf("Lookup(local) = %q, want randomized?", got)
	}
	if got := Lookup("zz:zz"); got != "" {
		t.Fatalf("Lookup(short) = %q, want empty", got)
	}
}
