package config

import (
	"errors"
	"testing"
)

func TestSpoofRequiresAcknowledgement(t *testing.T) {
	if _, err := Parse([]string{"-spoof"}); !errors.Is(err, ErrSpoofUnauthorized) {
		t.Fatalf("spoof without ack: err = %v, want ErrSpoofUnauthorized", err)
	}

	c, err := Parse([]string{"-spoof", "-i-own-this-network"})
	if err != nil {
		t.Fatalf("spoof with ack: unexpected err %v", err)
	}
	if !c.Spoof || !c.OwnNetwork {
		t.Fatalf("spoof with ack: got %+v", c)
	}
}

func TestPassiveNeedsNoAcknowledgement(t *testing.T) {
	c, err := Parse(nil)
	if err != nil {
		t.Fatalf("passive: unexpected err %v", err)
	}
	if c.Spoof {
		t.Error("spoof defaulted to true")
	}
}

// The acknowledgement alone, without -spoof, is harmless and must not error.
func TestAcknowledgementWithoutSpoof(t *testing.T) {
	if _, err := Parse([]string{"-i-own-this-network"}); err != nil {
		t.Fatalf("unexpected err %v", err)
	}
}
