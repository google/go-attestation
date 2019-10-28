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

package attributecert

import (
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"
)

func TestParseAttributeCerts(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to read test dir: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		filename := "testdata/" + file.Name()
		jsonfile := filename + ".json"
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			t.Fatalf("failed to read test data %s: %v", filename, err)
		}
		cert, err := ParseAttributeCertificate(data)
		if err != nil {
			t.Fatalf("failed to parse test data %s: %v", filename, err)
		}
		jsondata, err := ioutil.ReadFile(jsonfile)
		if err != nil {
			t.Fatalf("failed to read json test data %s: %v", jsonfile, err)
		}
		jsoncert, err := json.MarshalIndent(cert, "", "    ")
		if err != nil {
			t.Fatalf("failed to marshal %s to json: %v", filename, err)
		}
		if string(jsondata) != string(jsoncert) {
			t.Fatalf("%s fails to match test data", filename)
		}
	}
}
