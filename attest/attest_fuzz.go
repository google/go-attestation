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

//go:build gofuzz
// +build gofuzz

package attest

// FuzzParseAKPublic12 is an exported entrypoint for fuzzers to test
// ParseAKPublic TPM 1.2 blobs. This method should not be used for any
// other purpose.
func FuzzParseAKPublic12(data []byte) int {
	_, err := ParseAKPublic(TPMVersion12, data)
	if err != nil {
		return 0
	}
	return 1
}

// FuzzParseAKPublic20 is an exported entrypoint for fuzzers to test
// ParseAKPublic TPM 2.0 blobs. This method should not be used for any
// other purpose.
func FuzzParseAKPublic20(data []byte) int {
	_, err := ParseAKPublic(TPMVersion20, data)
	if err != nil {
		return 0
	}
	return 1
}

// FuzzParseEKCertificate is an exported entrypoint for fuzzers to test
// ParseEKCertificate. This method should not be used for any other purpose.
func FuzzParseEKCertificate(data []byte) int {
	_, err := ParseEKCertificate(data)
	if err != nil {
		return 0
	}
	return 1
}
