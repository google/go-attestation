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

  sudo apt-get -y install libssl-dev build-essential make trousers
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
}

setup_build_base
fetch_simulator
build_simulator
