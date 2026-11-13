// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type applicationTestLocks struct {
	gates    map[int64]chan struct{}
	attempts chan int64
}

func newApplicationTestLocks() *applicationTestLocks {
	return &applicationTestLocks{
		gates: map[int64]chan struct{}{
			ApplyOrUndoAdvisoryLockKey:  make(chan struct{}, 1),
			haproxyApplyAdvisoryLockKey: make(chan struct{}, 1),
		},
		attempts: make(chan int64, 16),
	}
}

func (l *applicationTestLocks) acquire(ctx context.Context, key int64) (func() error, error) {
	gate, ok := l.gates[key]
	if !ok {
		return nil, fmt.Errorf("unexpected lock key %d", key)
	}
	l.attempts <- key
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() error {
		once.Do(func() { <-gate })
		return nil
	}, nil
}

func TestApplicationMutationLeaseHasBoundedOwnership(t *testing.T) {
	e := &Engine{}
	locks := newApplicationTestLocks()
	ctx, release, err := e.lockApplicationMutation(t.Context(), locks.acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = release() }()
	<-locks.attempts
	_, nestedRelease, err := e.lockApplicationMutation(ctx, func(context.Context, int64) (func() error, error) {
		return nil, errors.New("nested operation attempted to acquire its own lock")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nestedRelease(); err != nil {
		t.Fatal(err)
	}
	foreign := &Engine{}
	foreignCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, foreignRelease, err := foreign.lockApplicationMutation(foreignCtx, locks.acquire)
	if err == nil {
		_ = foreignRelease()
		t.Fatal("another engine reused a foreign lease")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("foreign lease wait: %v", err)
	}
	<-locks.attempts
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	_, renewedRelease, err := e.lockApplicationMutation(ctx, locks.acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = renewedRelease() }()
	select {
	case key := <-locks.attempts:
		if key != ApplyOrUndoAdvisoryLockKey {
			t.Fatalf("reacquired unexpected lock: %d", key)
		}
	default:
		t.Fatal("released lease bypassed a fresh lock acquisition")
	}
}

func TestApplicationMutationCanApplyWhileBackgroundApplyWaits(t *testing.T) {
	e := &Engine{}
	locks := newApplicationTestLocks()
	clientCtx, cancelClient := context.WithCancel(t.Context())
	defer cancelClient()
	ctx, releaseMutation, err := e.lockApplicationMutation(clientCtx, locks.acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = releaseMutation() }()
	<-locks.attempts
	backgroundCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	backgroundResult := make(chan error, 1)
	go func() {
		release, err := e.lockApplyWith(backgroundCtx, locks.acquire)
		if err == nil {
			err = release()
		}
		backgroundResult <- err
	}()
	select {
	case key := <-locks.attempts:
		if key != ApplyOrUndoAdvisoryLockKey {
			t.Fatalf("background apply acquired out of order: %d", key)
		}
	case <-backgroundCtx.Done():
		t.Fatal("background apply did not wait on the mutation gate")
	}
	// applyContext uses WithoutCancel: its copied values must preserve the
	// active lease, even if the original client has disconnected.
	cancelClient()
	applyCtx, applyCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer applyCancel()
	releaseApply, err := e.lockApplyWith(applyCtx, locks.acquire)
	if err != nil {
		t.Fatalf("mutating request deadlocked behind a waiting background apply: %v", err)
	}
	if err := releaseApply(); err != nil {
		t.Fatal(err)
	}
	if err := releaseApply(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-backgroundResult:
		t.Fatalf("background apply passed the still-active mutation gate: %v", err)
	default:
	}
	if err := releaseMutation(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-backgroundResult:
		if err != nil {
			t.Fatalf("background apply did not resume: %v", err)
		}
	case <-backgroundCtx.Done():
		t.Fatal("background apply remained blocked after mutation completed")
	}
}

func TestApplyLockFailureReleasesMutationGate(t *testing.T) {
	e := &Engine{}
	locks := newApplicationTestLocks()
	edgeErr, releaseErr := errors.New("edge lock failed"), errors.New("gate release failed")
	_, err := e.lockApplyWith(t.Context(), func(ctx context.Context, key int64) (func() error, error) {
		if key == haproxyApplyAdvisoryLockKey {
			return nil, edgeErr
		}
		release, err := locks.acquire(ctx, key)
		return func() error {
			if err := release(); err != nil {
				return err
			}
			return releaseErr
		}, err
	})
	if !errors.Is(err, edgeErr) || !errors.Is(err, releaseErr) {
		t.Fatalf("acquisition/cleanup failure lost: %v", err)
	}
	if len(e.applySem) != 0 || len(locks.gates[ApplyOrUndoAdvisoryLockKey]) != 0 {
		t.Fatal("failed apply retained a local or mutation lock")
	}
}
