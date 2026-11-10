// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"os"
	"testing"

	"github.com/easy-waf/easy-waf/internal/testcert"
)

func TestMain(m *testing.M) {
	// Golden configs name these paths. The keys are created here and are not
	// part of the repository.
	testcert.MustGoldenBundles("testdata/golden/certs")
	os.Exit(m.Run())
}
