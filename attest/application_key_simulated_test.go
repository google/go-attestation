// Copyright 2026 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//go:build !localtest && cgo && !gofuzz && !windows
// +build !localtest,cgo,!gofuzz,!windows

// NOTE: simulator requires cgo, hence the build tag. The simulator does not
// build on Windows.

package attest

import (
	"testing"
)

func TestSimKeyCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCreateAndLoad(t, tpm)
}

func TestSimKeySign(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeySign(t, tpm)
}

func TestSimKeySignErrors(t *testing.T) {
	testKeySignErrors(t, func(t *testing.T) *TPM {
		sim, tpm := setupSimulatedTPM(t)
		t.Cleanup(func() { sim.Close() })
		return tpm
	})
}

func TestSimKeyOpts(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyOpts(t, tpm)
}
