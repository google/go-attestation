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

package attest

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// serializedKey represents a loadable, TPM-backed key.
type serializedKey struct {
	Encoding   KeyEncoding `json:"KeyEncoding"`
	Purpose    KeyPurpose
	Platform   string
	TPMVersion TPMVersion

	// Public represents the public key, in a TPM-specific format.
	Public []byte
	// The following fields are only valid for TPM 2.0 hardware, holding
	// information returned as the result to a TPM2_CertifyCreation command.
	// These are stored alongside the key for later use, as the certification
	// can only be obtained immediately after the key is generated.
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte

	// Name is only valid for KeyEncodingOSManaged.
	Name string
	// Blob represents the key material for KeyEncodingEncrypted keys.
	Blob []byte `json:"KeyBlob"`
}

// Serialize represents the key in a persistent format which may be
// loaded at a later time using deserializeKey().
func (k *serializedKey) Serialize() ([]byte, error) {
	k.Platform = runtime.GOOS
	return json.Marshal(k)
}

func deserializeKey(b []byte, version TPMVersion) (*serializedKey, error) {
	var k serializedKey
	var err error
	if err = json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("json.Unmarshal() failed: %v", err)
	}

	if k.Platform != "" && k.Platform != runtime.GOOS {
		return nil, fmt.Errorf("key for different platform: %s", k.Platform)
	}
	if k.TPMVersion != version {
		return nil, fmt.Errorf("key for different TPM version: %v", k.TPMVersion)
	}

	return &k, nil
}
