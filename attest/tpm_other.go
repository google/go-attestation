// Copyright 2019 Google Inc.
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

// +build gofuzz

package attest

type platformTPM struct {
}

func probeSystemTPMs() ([]probedTPM, error) {
	return nil, nil
}

func openTPM(tpm probedTPM) (*TPM, error) {
	return nil, nil
}

func (t *platformTPM) tpmVersion() TPMVersion {
	return TPMVersionAgnostic
}

func (t *platformTPM) close() error {
	return nil
}

func (t *platformTPM) info() (*TPMInfo, error) {
	return nil, nil
}

func (t *platformTPM) loadAIK(opaqueBlob []byte) (*AIK, error) {
	return nil, nil
}

func (t *platformTPM) eks() ([]EK, error) {
	return nil, nil
}

func (t *platformTPM) newAIK(opts *AIKConfig) (*AIK, error) {
	return nil, nil
}

func (t *platformTPM) pcrs(alg HashAlg) ([]PCR, error) {
	return nil, nil
}

func (t *platformTPM) measurementLog() ([]byte, error) {
	return nil, nil
}

