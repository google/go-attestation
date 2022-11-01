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
	"crypto/x509"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestVerifyAttributeCert(t *testing.T) {
	testfiles := [...]string{"testdata/Intel_nuc_pc2.cer",
		"testdata/Intel_nuc_pc.cer",
		"testdata/Intel_pc2.cer",
		"testdata/Intel_pc3.cer",
	}
	data, err := os.ReadFile("testdata/IntelSigningKey_20April2017.cer")
	if err != nil {
		t.Fatalf("failed to read Intel intermediate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatalf("failed to parse Intel intermediate certificate: %v", err)
	}

	for _, filename := range testfiles {
		data, err = os.ReadFile(filename)
		if err != nil {
			t.Fatalf("failed to read %s: %v", filename, err)
		}

		attributecert, err := ParseAttributeCertificate(data)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", filename, err)
		}

		err = attributecert.CheckSignatureFrom(cert)
		if err != nil {
			t.Fatalf("failed to verify signature on %s: %v", filename, err)
		}
	}
}

func TestParseAttributeCerts(t *testing.T) {
	files, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to read test dir: %v", err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), "Signing") {
			continue
		}
		if strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		filename := "testdata/" + file.Name()
		jsonfile := filename + ".json"
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("failed to read test data %s: %v", filename, err)
		}
		got, err := ParseAttributeCertificate(data)
		if err != nil {
			t.Fatalf("failed to parse test data %s: %v", filename, err)
		}
		jsondata, err := os.ReadFile(jsonfile)
		if err != nil {
			t.Fatalf("failed to read json test data %s: %v", jsonfile, err)
		}
		var want AttributeCertificate
		if err := json.Unmarshal(jsondata, &want); err != nil {
			t.Fatalf("failed to unmarshal file %s: %v", filename, err)
		}
		if !reflect.DeepEqual(&want, got) {
			t.Fatalf("%s fails to match test data", filename)
		}
	}
}
