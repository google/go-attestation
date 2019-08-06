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

// TCGVendorID represents a unique TCG manufacturer code.
// The canonical reference used is located at:
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.01-Revision-1.00.pdf
type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1229081856: "IBM",
	1213220096: "HPE",
	1297303124: "Microsoft",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576515: "SMSC",
	1398033696: "ST Microelectronics",
	1397576526: "Samsung",
	1397641984: "Sinosun",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1380926275: "Fuzhou Rockchip",
	1196379975: "Google",
}

func (id TCGVendorID) String() string {
	return vendors[id]
}
