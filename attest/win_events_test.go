// Copyright 2020 Google Inc.
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
	"io/ioutil"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParseWinEvents(t *testing.T) {
	want := &WinEvents{
		BootCount:            4,
		DEPEnabled:           true,
		CodeIntegrityEnabled: true,
		BitlockerUnlocks:     []BitlockerStatus{0, 0},
		LoadedModules: map[string]WinModuleLoad{
			"32e9370e7b5990dead1aba5187b8f3f70b1e19f70e5116286345113014822198": WinModuleLoad{
				ImageBase:        []uint64{62648320},
				AuthenticodeHash: []byte{50, 233, 55, 14, 123, 89, 144, 222, 173, 26, 186, 81, 135, 184, 243, 247, 11, 30, 25, 247, 14, 81, 22, 40, 99, 69, 17, 48, 20, 130, 33, 152},
			},
			"d4295492dde6fb4b7c71451d5d4fb96b39c1b1438376aaf15e2b56c2d5687c00": WinModuleLoad{
				ImageBase:        []uint64{77512704},
				AuthenticodeHash: []byte{212, 41, 84, 146, 221, 230, 251, 75, 124, 113, 69, 29, 93, 79, 185, 107, 57, 193, 177, 67, 131, 118, 170, 241, 94, 43, 86, 194, 213, 104, 124, 0},
			},
			"a60dd76d706ec71b66b0cd513226b7ee9259d5468c98d1da6617c02bd12c4f5d": WinModuleLoad{
				ImageBase:        []uint64{79519744},
				AuthenticodeHash: []byte{166, 13, 215, 109, 112, 110, 199, 27, 102, 176, 205, 81, 50, 38, 183, 238, 146, 89, 213, 70, 140, 152, 209, 218, 102, 23, 192, 43, 209, 44, 79, 93},
			},
			"84128ea279e82f208150eea53db69733d8822a885fab55e5f9d858038a911065": WinModuleLoad{
				ImageBase:        []uint64{83161088},
				AuthenticodeHash: []byte{132, 18, 142, 162, 121, 232, 47, 32, 129, 80, 238, 165, 61, 182, 151, 51, 216, 130, 42, 136, 95, 171, 85, 229, 249, 216, 88, 3, 138, 145, 16, 101},
			},
			"797493b483155c0a477a81c2729c28e79da379c6d5bdd1314b76f595fd8f2f52": WinModuleLoad{
				ImageBase:        []uint64{59179008},
				AuthenticodeHash: []byte{121, 116, 147, 180, 131, 21, 92, 10, 71, 122, 129, 194, 114, 156, 40, 231, 157, 163, 121, 198, 213, 189, 209, 49, 75, 118, 245, 149, 253, 143, 47, 82},
			},
			"6928a3ff67aaa32b3cca243c47ded3f50f360a496bed22eca5fc68b81905fa73": WinModuleLoad{
				ImageBase:        []uint64{54525952},
				AuthenticodeHash: []byte{105, 40, 163, 255, 103, 170, 163, 43, 60, 202, 36, 60, 71, 222, 211, 245, 15, 54, 10, 73, 107, 237, 34, 236, 165, 252, 104, 184, 25, 5, 250, 115},
			},
			"f443c47def8ae36ca1b9cdd863708d9f93a8c5815da013e95ae96acf786a7b38": WinModuleLoad{
				ImageBase:        []uint64{57032704},
				AuthenticodeHash: []byte{244, 67, 196, 125, 239, 138, 227, 108, 161, 185, 205, 216, 99, 112, 141, 159, 147, 168, 197, 129, 93, 160, 19, 233, 90, 233, 106, 207, 120, 106, 123, 56},
			},
			"7761c2c541c93e142aca3a3225ea783553002c4069f59af7e5673a4940f663b1": WinModuleLoad{
				ImageBase:        []uint64{76763136},
				AuthenticodeHash: []byte{119, 97, 194, 197, 65, 201, 62, 20, 42, 202, 58, 50, 37, 234, 120, 53, 83, 0, 44, 64, 105, 245, 154, 247, 229, 103, 58, 73, 64, 246, 99, 177},
			},
			"add8e66198c26fe184c9c57b3c3c905a3c31394b4fa53a72f23677cd1f952769": WinModuleLoad{
				ImageBase:        []uint64{81506304},
				AuthenticodeHash: []byte{173, 216, 230, 97, 152, 194, 111, 225, 132, 201, 197, 123, 60, 60, 144, 90, 60, 49, 57, 75, 79, 165, 58, 114, 242, 54, 119, 205, 31, 149, 39, 105},
			},
			"bf55e397daef06c0cc769bb5c3c71bb47e497269abfac20a90f51fb3f584b322": WinModuleLoad{
				ImageBase:        []uint64{90759168},
				AuthenticodeHash: []byte{191, 85, 227, 151, 218, 239, 6, 192, 204, 118, 155, 181, 195, 199, 27, 180, 126, 73, 114, 105, 171, 250, 194, 10, 144, 245, 31, 179, 245, 132, 179, 34},
			},
			"44e1ea32b24a048832eeda3d658743a68836aaa2e31ca2e0ee4e24ecb2f74619": WinModuleLoad{
				ImageBase:        []uint64{21626880},
				AuthenticodeHash: []byte{68, 225, 234, 50, 178, 74, 4, 136, 50, 238, 218, 61, 101, 135, 67, 166, 136, 54, 170, 162, 227, 28, 162, 224, 238, 78, 36, 236, 178, 247, 70, 25},
			},
			"7f14f4f84fb8b6c7c34e461b6a34af1ae8d29d95bea89056563273f8a0a99ec8": WinModuleLoad{
				ImageBase:        []uint64{94412800},
				AuthenticodeHash: []byte{127, 20, 244, 248, 79, 184, 182, 199, 195, 78, 70, 27, 106, 52, 175, 26, 232, 210, 157, 149, 190, 168, 144, 86, 86, 50, 115, 248, 160, 169, 158, 200},
			},
			"df65fd5192e9344f180d9253558197fb1a57ea8c62d869aad2d141ac5bea2a75": WinModuleLoad{
				ImageBase:        []uint64{79597568},
				AuthenticodeHash: []byte{223, 101, 253, 81, 146, 233, 52, 79, 24, 13, 146, 83, 85, 129, 151, 251, 26, 87, 234, 140, 98, 216, 105, 170, 210, 209, 65, 172, 91, 234, 42, 117},
			},
			"e0c06ca5eb27ba7016cd49df05e40490f2d4553d2f21d4da4235cdd430a68a8e": WinModuleLoad{
				ImageBase:        []uint64{62148608},
				AuthenticodeHash: []byte{224, 192, 108, 165, 235, 39, 186, 112, 22, 205, 73, 223, 5, 228, 4, 144, 242, 212, 85, 61, 47, 33, 212, 218, 66, 53, 205, 212, 48, 166, 138, 142},
			},
			"f6d3874eee0c8b57c12a2987a3d1608a842fca538aebcb476b91c579bd1205e6": WinModuleLoad{
				ImageBase:        []uint64{62595072},
				AuthenticodeHash: []byte{246, 211, 135, 78, 238, 12, 139, 87, 193, 42, 41, 135, 163, 209, 96, 138, 132, 47, 202, 83, 138, 235, 203, 71, 107, 145, 197, 121, 189, 18, 5, 230},
			},
			"9dd8d4e18c3699f801da54df94f17fe336c259e4c7f8bb40b62c71564a1c5381": WinModuleLoad{
				ImageBase:        []uint64{76320768},
				AuthenticodeHash: []byte{157, 216, 212, 225, 140, 54, 153, 248, 1, 218, 84, 223, 148, 241, 127, 227, 54, 194, 89, 228, 199, 248, 187, 64, 182, 44, 113, 86, 74, 28, 83, 129},
			},
			"664a94cc5824aed3b582b68a899829bcfaad76411df2fa5a84a76ff8bf1e245e": WinModuleLoad{
				ImageBase:        []uint64{62767104},
				AuthenticodeHash: []byte{102, 74, 148, 204, 88, 36, 174, 211, 181, 130, 182, 138, 137, 152, 41, 188, 250, 173, 118, 65, 29, 242, 250, 90, 132, 167, 111, 248, 191, 30, 36, 94},
			},
			"c7607206759f638170c29124e45c96364383f9ea83c5fc09f374777c749cec36": WinModuleLoad{
				ImageBase:        []uint64{61927424},
				AuthenticodeHash: []byte{199, 96, 114, 6, 117, 159, 99, 129, 112, 194, 145, 36, 228, 92, 150, 54, 67, 131, 249, 234, 131, 197, 252, 9, 243, 116, 119, 124, 116, 156, 236, 54},
			},
			"0fdce7d71936f79445e7d2c84cbeb97c948d3730e0b839166b0a4e625c2d4547": WinModuleLoad{
				ImageBase:        []uint64{81416192},
				AuthenticodeHash: []byte{15, 220, 231, 215, 25, 54, 247, 148, 69, 231, 210, 200, 76, 190, 185, 124, 148, 141, 55, 48, 224, 184, 57, 22, 107, 10, 78, 98, 92, 45, 69, 71},
			},
			"9ef6edda34d6fc95ec095fd19433fa26c0fbb65cafa921b6235570299aa31723": WinModuleLoad{
				ImageBase:        []uint64{56209408},
				AuthenticodeHash: []byte{158, 246, 237, 218, 52, 214, 252, 149, 236, 9, 95, 209, 148, 51, 250, 38, 192, 251, 182, 92, 175, 169, 33, 182, 35, 85, 112, 41, 154, 163, 23, 35},
			},
			"90168a8da8167ce4540995e670f138e03a6c386b4d7af33d9109105de16be6fe": WinModuleLoad{
				ImageBase:        []uint64{78127104},
				AuthenticodeHash: []byte{144, 22, 138, 141, 168, 22, 124, 228, 84, 9, 149, 230, 112, 241, 56, 224, 58, 108, 56, 107, 77, 122, 243, 61, 145, 9, 16, 93, 225, 107, 230, 254},
			},
			"7d89cfc48ae1097761b64a44a588ba711360b5b5afe780e1c2d5f333e101cd88": WinModuleLoad{
				ImageBase:        []uint64{81285120},
				AuthenticodeHash: []byte{125, 137, 207, 196, 138, 225, 9, 119, 97, 182, 74, 68, 165, 136, 186, 113, 19, 96, 181, 181, 175, 231, 128, 225, 194, 213, 243, 51, 225, 1, 205, 136},
			},
			"4d0cff77cba5d2e72e8af943f2c0ff9c47abef2beedd3368460bea17ceaa07af": WinModuleLoad{
				ImageBase:        []uint64{42012672},
				AuthenticodeHash: []byte{77, 12, 255, 119, 203, 165, 210, 231, 46, 138, 249, 67, 242, 192, 255, 156, 71, 171, 239, 43, 238, 221, 51, 104, 70, 11, 234, 23, 206, 170, 7, 175},
			},
			"ea3261292257b41b1c25e794bd3367497c39c9c07b1c75217ee2ca1b591e3310": WinModuleLoad{
				ImageBase:        []uint64{77307904},
				AuthenticodeHash: []byte{234, 50, 97, 41, 34, 87, 180, 27, 28, 37, 231, 148, 189, 51, 103, 73, 124, 57, 201, 192, 123, 28, 117, 33, 126, 226, 202, 27, 89, 30, 51, 16},
			},
			"055a36a9921b98cc04042ca95249c7eca655536868dafcec7508947ebe5e71f4": WinModuleLoad{
				ImageBase:        []uint64{82952192},
				AuthenticodeHash: []byte{5, 90, 54, 169, 146, 27, 152, 204, 4, 4, 44, 169, 82, 73, 199, 236, 166, 85, 83, 104, 104, 218, 252, 236, 117, 8, 148, 126, 190, 94, 113, 244},
			},
			"7a12a17b7cd7ed3f714557829e9d69f084294ca06c030480852f838987a29036": WinModuleLoad{
				ImageBase:        []uint64{57573376},
				AuthenticodeHash: []byte{122, 18, 161, 123, 124, 215, 237, 63, 113, 69, 87, 130, 158, 157, 105, 240, 132, 41, 76, 160, 108, 3, 4, 128, 133, 47, 131, 137, 135, 162, 144, 54},
			},
			"bd2c3254d9df155dd6d39cbbd946f2b9c3bbcef4ff19aa9b60ec785d66c38d73": WinModuleLoad{
				ImageBase:        []uint64{88080384},
				AuthenticodeHash: []byte{189, 44, 50, 84, 217, 223, 21, 93, 214, 211, 156, 187, 217, 70, 242, 185, 195, 187, 206, 244, 255, 25, 170, 155, 96, 236, 120, 93, 102, 195, 141, 115},
			},
			"975e2d723e42796f915cf4afd824d9ba77e00c31e4b621064928965b147ad8ba": WinModuleLoad{
				ImageBase:        []uint64{79790080},
				AuthenticodeHash: []byte{151, 94, 45, 114, 62, 66, 121, 111, 145, 92, 244, 175, 216, 36, 217, 186, 119, 224, 12, 49, 228, 182, 33, 6, 73, 40, 150, 91, 20, 122, 216, 186},
			},
			"ec130af958cefaaab36367315b5faffe55a7a0c9408c48c5f90a3ba991499be3": WinModuleLoad{
				ImageBase:        []uint64{94478336},
				AuthenticodeHash: []byte{236, 19, 10, 249, 88, 206, 250, 170, 179, 99, 103, 49, 91, 95, 175, 254, 85, 167, 160, 201, 64, 140, 72, 197, 249, 10, 59, 169, 145, 73, 155, 227},
			},
			"a13d7f5101ae1f0ba206da086db0f8fc060100ad73207756048026957a357ac5": WinModuleLoad{
				ImageBase:        []uint64{61997056},
				AuthenticodeHash: []byte{161, 61, 127, 81, 1, 174, 31, 11, 162, 6, 218, 8, 109, 176, 248, 252, 6, 1, 0, 173, 115, 32, 119, 86, 4, 128, 38, 149, 122, 53, 122, 197},
			},
			"eda40f4a998c767878f0d34b9b254c78883019ca677a2cf535b5cd78485e6e65": WinModuleLoad{
				ImageBase:        []uint64{61779968},
				AuthenticodeHash: []byte{237, 164, 15, 74, 153, 140, 118, 120, 120, 240, 211, 75, 155, 37, 76, 120, 136, 48, 25, 202, 103, 122, 44, 245, 53, 181, 205, 120, 72, 94, 110, 101},
			},
			"7806d7d5d0f48276fe93d9a4187d7e3c38baee7e8d64d8a9b4ad5f26d0ed4a83": WinModuleLoad{
				ImageBase:        []uint64{77029376},
				AuthenticodeHash: []byte{120, 6, 215, 213, 208, 244, 130, 118, 254, 147, 217, 164, 24, 125, 126, 60, 56, 186, 238, 126, 141, 100, 216, 169, 180, 173, 95, 38, 208, 237, 74, 131},
			},
			"ec980190879bf4946c0a4bbabed377df0a43d7379d5f8caefc32457a3b958054": WinModuleLoad{
				ImageBase:        []uint64{57470976},
				AuthenticodeHash: []byte{236, 152, 1, 144, 135, 155, 244, 148, 108, 10, 75, 186, 190, 211, 119, 223, 10, 67, 215, 55, 157, 95, 140, 174, 252, 50, 69, 122, 59, 149, 128, 84},
			},
			"a1dddaad7234448a426511512328eb6647c34b30979ae7c258686ea46c4a86ef": WinModuleLoad{
				ImageBase:        []uint64{61861888},
				AuthenticodeHash: []byte{161, 221, 218, 173, 114, 52, 68, 138, 66, 101, 17, 81, 35, 40, 235, 102, 71, 195, 75, 48, 151, 154, 231, 194, 88, 104, 110, 164, 108, 74, 134, 239},
			},
			"5b4f87788f6f845c885af2ab7cb388a786ce8759a5ec1742ebfed59ba3c6dfd2": WinModuleLoad{
				ImageBase:        []uint64{62697472},
				AuthenticodeHash: []byte{91, 79, 135, 120, 143, 111, 132, 92, 136, 90, 242, 171, 124, 179, 136, 167, 134, 206, 135, 89, 165, 236, 23, 66, 235, 254, 213, 155, 163, 198, 223, 210},
			},
			"70d2d2a4053346b102bd89013e69fb8b6761a603ac46a9a241ab7f39419c9df7": WinModuleLoad{
				ImageBase:        []uint64{82268160},
				AuthenticodeHash: []byte{112, 210, 210, 164, 5, 51, 70, 177, 2, 189, 137, 1, 62, 105, 251, 139, 103, 97, 166, 3, 172, 70, 169, 162, 65, 171, 127, 57, 65, 156, 157, 247},
			},
			"d8dd214b8c992cabbf6726cf2d04b28f1fb6edc588da855401165c7d566214a0": WinModuleLoad{
				ImageBase:        []uint64{93806592},
				AuthenticodeHash: []byte{216, 221, 33, 75, 140, 153, 44, 171, 191, 103, 38, 207, 45, 4, 178, 143, 31, 182, 237, 197, 136, 218, 133, 84, 1, 22, 92, 125, 86, 98, 20, 160},
			},
			"a1fac76e62705c3ae93cdfb8ac205af581ce5046c809d5dcccbfc78cb9991648": WinModuleLoad{
				ImageBase:        []uint64{57622528},
				AuthenticodeHash: []byte{161, 250, 199, 110, 98, 112, 92, 58, 233, 60, 223, 184, 172, 32, 90, 245, 129, 206, 80, 70, 200, 9, 213, 220, 204, 191, 199, 140, 185, 153, 22, 72},
			},
			"e82af894a692468588d59407d5732dbcfcc9d25b16410e009dc79d298e924592": WinModuleLoad{
				ImageBase:        []uint64{82894848},
				AuthenticodeHash: []byte{232, 42, 248, 148, 166, 146, 70, 133, 136, 213, 148, 7, 213, 115, 45, 188, 252, 201, 210, 91, 22, 65, 14, 0, 157, 199, 157, 41, 142, 146, 69, 146},
			},
			"a677be0fa7102b3fcfdce920b2e78f884bee40e63497b0566a9ddec6e59c3cab": WinModuleLoad{
				ImageBase:        []uint64{60162048},
				AuthenticodeHash: []byte{166, 119, 190, 15, 167, 16, 43, 63, 207, 220, 233, 32, 178, 231, 143, 136, 75, 238, 64, 230, 52, 151, 176, 86, 106, 157, 222, 198, 229, 156, 60, 171},
			},
			"b6d28f4cc9161058e145aa22558c7712282fd016f93cea10030d3d767b30f54d": WinModuleLoad{
				ImageBase:        []uint64{56283136},
				AuthenticodeHash: []byte{182, 210, 143, 76, 201, 22, 16, 88, 225, 69, 170, 34, 85, 140, 119, 18, 40, 47, 208, 22, 249, 60, 234, 16, 3, 13, 61, 118, 123, 48, 245, 77},
			},
			"e940e1ef14a6669ee6ee5eb11c68d3e5914bd2635b1444315a3b3212d39c9c73": WinModuleLoad{
				ImageBase:        []uint64{56868864},
				AuthenticodeHash: []byte{233, 64, 225, 239, 20, 166, 102, 158, 230, 238, 94, 177, 28, 104, 211, 229, 145, 75, 210, 99, 91, 20, 68, 49, 90, 59, 50, 18, 211, 156, 156, 115},
			},
			"a92d5773fb86bb9faf76d8de0dad3ef23e9a1bf43886e963ccfc4394479d69fd": WinModuleLoad{
				ImageBase:        []uint64{62484480},
				AuthenticodeHash: []byte{169, 45, 87, 115, 251, 134, 187, 159, 175, 118, 216, 222, 13, 173, 62, 242, 62, 154, 27, 244, 56, 134, 233, 99, 204, 252, 67, 148, 71, 157, 105, 253},
			},
			"ddca19d05f692bd686fb69ded088b2279ecafc987a8d18a4b0a78497133f72d8": WinModuleLoad{
				ImageBase:        []uint64{79896576},
				AuthenticodeHash: []byte{221, 202, 25, 208, 95, 105, 43, 214, 134, 251, 105, 222, 208, 136, 178, 39, 158, 202, 252, 152, 122, 141, 24, 164, 176, 167, 132, 151, 19, 63, 114, 216},
			},
			"2c6360318c44ea22eec015b1423333eaf385b363637ae92e00584310843bbee4": WinModuleLoad{
				ImageBase:        []uint64{83656704},
				AuthenticodeHash: []byte{44, 99, 96, 49, 140, 68, 234, 34, 238, 192, 21, 177, 66, 51, 51, 234, 243, 133, 179, 99, 99, 122, 233, 46, 0, 88, 67, 16, 132, 59, 190, 228},
			},
			"d655794a88bafea498ae95562a69c5ce082041a74d65f105375fa6caddb5356a": WinModuleLoad{
				ImageBase:        []uint64{54525952},
				AuthenticodeHash: []byte{214, 85, 121, 74, 136, 186, 254, 164, 152, 174, 149, 86, 42, 105, 197, 206, 8, 32, 65, 167, 77, 101, 241, 5, 55, 95, 166, 202, 221, 181, 53, 106},
			},
			"bd2173c98e145abd1551da6bdab431e0e2b906d0463b0679a68ab333d67fb332": WinModuleLoad{
				ImageBase:        []uint64{59240448},
				AuthenticodeHash: []byte{189, 33, 115, 201, 142, 20, 90, 189, 21, 81, 218, 107, 218, 180, 49, 224, 226, 185, 6, 208, 70, 59, 6, 121, 166, 138, 179, 51, 214, 127, 179, 50},
			},
			"b41212f59c1037f3cefe2d335e7b8d23ecdf719b03dc0199b911516ae7248e75": WinModuleLoad{
				ImageBase:        []uint64{75497472},
				AuthenticodeHash: []byte{180, 18, 18, 245, 156, 16, 55, 243, 206, 254, 45, 51, 94, 123, 141, 35, 236, 223, 113, 155, 3, 220, 1, 153, 185, 17, 81, 106, 231, 36, 142, 117},
			},
			"e9f797708644a274064b33ce3485843bd185de893709f3dfbe312714859b248b": WinModuleLoad{
				ImageBase:        []uint64{62861312},
				AuthenticodeHash: []byte{233, 247, 151, 112, 134, 68, 162, 116, 6, 75, 51, 206, 52, 133, 132, 59, 209, 133, 222, 137, 55, 9, 243, 223, 190, 49, 39, 20, 133, 155, 36, 139},
			},
			"d8b81d1f33674943d94e0d26bab1806b0d394a01a7965ded873bd477e6362576": WinModuleLoad{
				ImageBase:        []uint64{80093184},
				AuthenticodeHash: []byte{216, 184, 29, 31, 51, 103, 73, 67, 217, 78, 13, 38, 186, 177, 128, 107, 13, 57, 74, 1, 167, 150, 93, 237, 135, 59, 212, 119, 230, 54, 37, 118},
			},
			"2bedd1589410b6fa13c82f35db735025b6a160595922750248771f5abd0fee58": WinModuleLoad{
				ImageBase:        []uint64{80875520},
				AuthenticodeHash: []byte{43, 237, 209, 88, 148, 16, 182, 250, 19, 200, 47, 53, 219, 115, 80, 37, 182, 161, 96, 89, 89, 34, 117, 2, 72, 119, 31, 90, 189, 15, 238, 88},
			},
			"bb83c355972dfab69007eaacf252d611222cbfc8f542a3adb55bc1fec0c8dbe6": WinModuleLoad{
				ImageBase:        []uint64{82149376},
				AuthenticodeHash: []byte{187, 131, 195, 85, 151, 45, 250, 182, 144, 7, 234, 172, 242, 82, 214, 17, 34, 44, 191, 200, 245, 66, 163, 173, 181, 91, 193, 254, 192, 200, 219, 230},
			},
			"8f75730144e8887d6db5b73c3aff856f5924031786402e6fd64ba0509ebd0613": WinModuleLoad{
				ImageBase:        []uint64{94257152},
				AuthenticodeHash: []byte{143, 117, 115, 1, 68, 232, 136, 125, 109, 181, 183, 60, 58, 255, 133, 111, 89, 36, 3, 23, 134, 64, 46, 111, 214, 75, 160, 80, 158, 189, 6, 19},
			},
			"ac4f4b1bf99124bfb6af0901a2f90c43aea3d2aedcfc8cf0343c3f463e427c0f": WinModuleLoad{
				ImageBase:        []uint64{54575104},
				AuthenticodeHash: []byte{172, 79, 75, 27, 249, 145, 36, 191, 182, 175, 9, 1, 162, 249, 12, 67, 174, 163, 210, 174, 220, 252, 140, 240, 52, 60, 63, 70, 62, 66, 124, 15},
			},
			"fe3e3f4bd0d28dfc743dca0e2ce180ccee714284a181c7fa9c10c679ecb39bbc": WinModuleLoad{
				ImageBase:        []uint64{77393920},
				AuthenticodeHash: []byte{254, 62, 63, 75, 208, 210, 141, 252, 116, 61, 202, 14, 44, 225, 128, 204, 238, 113, 66, 132, 161, 129, 199, 250, 156, 16, 198, 121, 236, 179, 155, 188},
			},
			"fa473b75dda617e177a5da382b8c21ef302147656f48319747e0bcef51be5667": WinModuleLoad{
				ImageBase:        []uint64{80769024},
				AuthenticodeHash: []byte{250, 71, 59, 117, 221, 166, 23, 225, 119, 165, 218, 56, 43, 140, 33, 239, 48, 33, 71, 101, 111, 72, 49, 151, 71, 224, 188, 239, 81, 190, 86, 103},
			},
			"96a1ba1d5b56ddc7449f414e750a255ed43819f92e59d1509d6452df6594b6ba": WinModuleLoad{
				ImageBase:        []uint64{94597120},
				AuthenticodeHash: []byte{150, 161, 186, 29, 91, 86, 221, 199, 68, 159, 65, 78, 117, 10, 37, 94, 212, 56, 25, 249, 46, 89, 209, 80, 157, 100, 82, 223, 101, 148, 182, 186},
			},
			"4428d1d3f18269950c90ddb8c92633930d290c673b906aa8a1e38700c651597a": WinModuleLoad{
				ImageBase:        []uint64{59293696},
				AuthenticodeHash: []byte{68, 40, 209, 211, 241, 130, 105, 149, 12, 144, 221, 184, 201, 38, 51, 147, 13, 41, 12, 103, 59, 144, 106, 168, 161, 227, 135, 0, 198, 81, 89, 122},
			},
			"d50919111c576bf2e169f60fd7f060c34222c1383a2cb7bdde4fafec963264d8": WinModuleLoad{
				ImageBase:        []uint64{56463360},
				AuthenticodeHash: []byte{213, 9, 25, 17, 28, 87, 107, 242, 225, 105, 246, 15, 215, 240, 96, 195, 66, 34, 193, 56, 58, 44, 183, 189, 222, 79, 175, 236, 150, 50, 100, 216},
			},
			"967a70a72f585497ec2a6159e34685e85c054d5b51993aabaff362b52fe58dc9": WinModuleLoad{
				ImageBase:        []uint64{58716160},
				AuthenticodeHash: []byte{150, 122, 112, 167, 47, 88, 84, 151, 236, 42, 97, 89, 227, 70, 133, 232, 92, 5, 77, 91, 81, 153, 58, 171, 175, 243, 98, 181, 47, 229, 141, 201},
			},
			"c215c189451643e3a3138b8868dba07bc873aa02d24145c752d2121ca6d1e169": WinModuleLoad{
				ImageBase:        []uint64{60919808},
				AuthenticodeHash: []byte{194, 21, 193, 137, 69, 22, 67, 227, 163, 19, 139, 136, 104, 219, 160, 123, 200, 115, 170, 2, 210, 65, 69, 199, 82, 210, 18, 28, 166, 209, 225, 105},
			},
			"8ff398bbdddb2f6eedffb49a1f7f13b042b6e4b1d440a54cde0f6182f902d79e": WinModuleLoad{
				ImageBase:        []uint64{82526208},
				AuthenticodeHash: []byte{143, 243, 152, 187, 221, 219, 47, 110, 237, 255, 180, 154, 31, 127, 19, 176, 66, 182, 228, 177, 212, 64, 165, 76, 222, 15, 97, 130, 249, 2, 215, 158},
			},
			"d191647257671c39ccff12f2ab7b2ad0a94187fec46a2cb7f43d8475b2a75bc3": WinModuleLoad{
				ImageBase:        []uint64{93757440},
				AuthenticodeHash: []byte{209, 145, 100, 114, 87, 103, 28, 57, 204, 255, 18, 242, 171, 123, 42, 208, 169, 65, 135, 254, 196, 106, 44, 183, 244, 61, 132, 117, 178, 167, 91, 195},
			},
			"cececd8896f1fa9977ca5a9c9903c88c209efc2dd5b3f430d43c129bb662c6a1": WinModuleLoad{
				ImageBase:        []uint64{52965376},
				AuthenticodeHash: []byte{206, 206, 205, 136, 150, 241, 250, 153, 119, 202, 90, 156, 153, 3, 200, 140, 32, 158, 252, 45, 213, 179, 244, 48, 212, 60, 18, 155, 182, 98, 198, 161},
			},
		},
		ELAM: map[string]WinELAM{
			"Windows Defender": WinELAM{Measured: []byte{0x06, 0x7d, 0x5b, 0x9d, 0xc5, 0x62, 0x7f, 0x97, 0xdc, 0xf3, 0xfe, 0xff, 0x60, 0x2a, 0x34, 0x2e, 0xd6, 0x98, 0xd2, 0xcc}},
		},
	}

	data, err := ioutil.ReadFile("testdata/windows_gcp_shielded_vm.json")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}

	el, err := ParseEventLog(dump.Log.Raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	events, err := el.Verify(dump.Log.PCRs)
	if err != nil {
		t.Fatalf("validating event log: %v", err)
	}

	winState, err := ParseWinEvents(events)
	if err != nil {
		t.Fatalf("ExtractSecurebootState() failed: %v", err)
	}

	if diff := cmp.Diff(winState, want, cmpopts.IgnoreUnexported(WinEvents{})); diff != "" {
		t.Errorf("Unexpected WinEvents (+got, -want):\n%s", diff)
	}
}
