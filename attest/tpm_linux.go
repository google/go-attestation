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

//go:build linux && !gofuzz
// +build linux,!gofuzz

package attest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	tpmRoot = "/sys/class/tpm"
)

// This will be initialized if we build with CGO (needed for TPM 1.2 support).
var getTPM12Impl func() (*TPM, error)

// InjectSimulatedTPMForTest returns a fake TPM that interfaces with
// the provided simulated TPM. This method should be used for testing
// only.
func InjectSimulatedTPMForTest(rwc io.ReadWriteCloser) *TPM {
	return &TPM{tpm: &wrappedTPM20{
		interf: TPMInterfaceCommandChannel,
		rwc:    &fakeCmdChannel{rwc},
	}}
}

func probeSystemTPMs() ([]probedTPM, error) {
	var tpms []probedTPM

	tpmDevs, err := os.ReadDir(tpmRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		for _, tpmDev := range tpmDevs {
			if strings.HasPrefix(tpmDev.Name(), "tpm") {
				tpm := probedTPM{
					Path: path.Join(tpmRoot, tpmDev.Name()),
				}

				if _, err := os.Stat(path.Join(tpm.Path, "caps")); err != nil {
					if !os.IsNotExist(err) {
						return nil, err
					}
					tpm.Version = TPMVersion20
				} else {
					tpm.Version = TPMVersion12
				}
				tpms = append(tpms, tpm)
			}
		}
	}

	return tpms, nil
}

type linuxCmdChannel struct {
	io.ReadWriteCloser
}

// MeasurementLog implements CommandChannelTPM20.
func (cc *linuxCmdChannel) MeasurementLog() ([]byte, error) {
	return os.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}

func openTPM(tpm probedTPM) (*TPM, error) {
	switch tpm.Version {
	case TPMVersion12:
		if getTPM12Impl == nil {
			return nil, errors.New("support for Linux TPM 1.2 disabled (build with CGO to enable)")
		}
		return getTPM12Impl()

	case TPMVersion20:
		interf := TPMInterfaceDirect
		// If the TPM has a kernel-provided resource manager, we should
		// use that instead of communicating directly.
		devPath := path.Join("/dev", path.Base(tpm.Path))
		f, err := os.ReadDir(path.Join(tpm.Path, "device", "tpmrm"))
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else if len(f) > 0 {
			devPath = path.Join("/dev", f[0].Name())
			interf = TPMInterfaceKernelManaged
		}

		rwc, err := tpm2.OpenTPM(devPath)
		if err != nil {
			return nil, err
		}

		return &TPM{tpm: &wrappedTPM20{
			interf: interf,
			rwc:    &linuxCmdChannel{rwc},
		}}, nil

	default:
		return nil, fmt.Errorf("unsuported TPM version: %v", tpm.Version)
	}
}
