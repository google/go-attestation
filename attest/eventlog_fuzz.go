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

// FuzzParseEventLog is an exported entrypoint for fuzzers to test the eventlog
// parser. This method should not be used for any other purpose.
func FuzzParseEventLog(data []byte) int {
	_, err := ParseEventLog(data)
	if err != nil {
		return 0
	}
	return 1
}
