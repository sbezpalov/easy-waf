package nft

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestApplyRulesetWithRollback_invalidRuleset(t *testing.T) {
	_, _, err := ApplyRulesetWithRollback(context.Background(), "table inet easy_waf { garbage", 90)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if errors.Is(err, os.ErrInvalid) {
		t.Fatal("expected nft -c error, not empty")
	}
}

func TestCommitRuleset_invalidToken(t *testing.T) {
	if err := CommitRuleset(context.Background(), "not-hex-token!"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
