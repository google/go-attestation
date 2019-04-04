#!/bin/bash
#
###############################################################################
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################
#
# Builds/installs a TPM 1.2 simulator + trousers, on a debian-based system.
# USAGE: ./setup_tpm12_simulator.sh <working dir>
set -e

SIMULATOR_TARBALL_URL="https://sourceforge.net/projects/ibmswtpm/files/tpm4769tar.gz/download"
SIMULATOR_TAR_SHA256="bb0a3f8003ca8ba71eb4a0852f0eb35a112297e28fce8e166412d4b2202c5010"

if [[ "${1}" == "" ]]; then
  >&2 echo "Error: Must specify the working directory as the first argument."
  exit 1
fi

PROJECT_ROOT=$(pwd)
BUILD_BASE="${1%/}" # Trim any trailing slash.
SIMULATOR_SRC="${BUILD_BASE}/simulator"

setup_build_base () {
  if [[ ! -d "${BUILD_BASE}" ]] && [[ -e "${BUILD_BASE}" ]]; then
    >&2 echo "Error: '${BUILD_BASE}' is not a directory."
    exit 1
  fi
  if [[ ! -e "${BUILD_BASE}" ]]; then
    mkdir -pv "${BUILD_BASE}"
  fi

  sudo apt-get -y install libssl-dev build-essential make trousers libtool autoconf tpm-tools
}

fetch_simulator () {
  TARBALL="${BUILD_BASE}/sim.tar.gz"

  if [[ ! -f "${TARBALL}" ]]; then
    wget -q -O "${TARBALL}" "${SIMULATOR_TARBALL_URL}"
  fi

  HSH=$(sha256sum "${TARBALL}" | cut -d" " -f1)
  if [[ "${HSH}" != "${SIMULATOR_TAR_SHA256}" ]]; then
    >&2 echo "'${TARBALL}' does not match expected SHA256."
    >&2 echo "Got: ${HSH}"
    >&2 echo "Want: ${SIMULATOR_TAR_SHA256}"
    exit 2
  fi

  mkdir -pv "${SIMULATOR_SRC}"
  tar -zxf "${TARBALL}" --directory "${SIMULATOR_SRC}"
}

build_simulator () {
  cp -v "${SIMULATOR_SRC}/tpm/makefile-tpm" "${SIMULATOR_SRC}/tpm/Makefile"
  cd "${SIMULATOR_SRC}/tpm" && make -j4
  cd "${SIMULATOR_SRC}/libtpm" && ./autogen
  cd "${SIMULATOR_SRC}/libtpm" && ./configure
  cd "${SIMULATOR_SRC}/libtpm" && make -j4
}

run_simulator () {
  mkdir -pv "${BUILD_BASE}/NVRAM"
  export TPM_PORT='6545'
  export TPM_PATH="${BUILD_BASE}/NVRAM"
  export TPM_SERVER_NAME='localhost'
  export TPM_SERVER_PORT='6545'
  ${SIMULATOR_SRC}/tpm/tpm_server &
  SIM_PID=$!
  echo "${SIM_PID}" > "${BUILD_BASE}/sim_pid"
  disown
  sleep 2
}

setup_tpm () {
  echo "Initializing the TPM..."
  ${SIMULATOR_SRC}/libtpm/utils/tpminit
  echo "Starting the TPM..."
  ${SIMULATOR_SRC}/libtpm/utils/tpmbios -cs

  ${SIMULATOR_SRC}/libtpm/utils/tpminit
  ${SIMULATOR_SRC}/libtpm/utils/tpmbios -cs
}

run_tcsd () {
  export TCSD_TCP_DEVICE_PORT='6545'
  sudo -E -u tss -g tss /usr/sbin/tcsd -f -e &
  TCSD_PID=$!
  echo "${TCSD_PID}" > "${BUILD_BASE}/tcsd_pid"
  disown
  sleep 1
  tpm_createek
  tpm_takeownership -yz
  tpm_nvdefine -i 268496896 -z -s 3800 -p OWNERWRITE
  go run -v "${PROJECT_ROOT}/ci/gen_ekcert.go"
  sleep 1
}

setup_build_base
fetch_simulator
build_simulator
run_simulator
setup_tpm
run_tcsd
