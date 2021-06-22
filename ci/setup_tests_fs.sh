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
# Sets up a root filesystem with files that symbolize the presence of a fake
# hardware VM. This filesystem can be chrooted into to run tests.
# USAGE: ./setup_tests_fs.sh <dir>
set -e

BASE_DIR="${1%/}" # Trim any trailing slash.

setup_base () {
  if [[ ! -d "${BASE_DIR}" ]] && [[ -e "${BASE_DIR}" ]]; then
    >&2 echo "Error: '${BASE_DIR}' is not a directory."
    exit 1
  fi
  if [[ ! -e "${BASE_DIR}" ]]; then
    mkdir -pv "${BASE_DIR}"
  else
    sudo umount ${BASE_DIR}/* || true
    rm -rfv ${BASE_DIR}/*
  fi
}

setup_mounts () {
  mkdir -v "${BASE_DIR}/bin"
  sudo mount --bind /bin "${BASE_DIR}/bin"
  mkdir -v "${BASE_DIR}/usr"
  sudo mount --bind /usr "${BASE_DIR}/usr"
  mkdir -v "${BASE_DIR}/var"
  sudo mount --bind /var "${BASE_DIR}/var"
  mkdir -v "${BASE_DIR}/tmp"
  sudo mount --bind /tmp "${BASE_DIR}/tmp"
  mkdir -v "${BASE_DIR}/lib"
  sudo mount --bind /lib "${BASE_DIR}/lib"
  mkdir -v "${BASE_DIR}/lib64"
  sudo mount --bind /lib64 "${BASE_DIR}/lib64"
  mkdir -v "${BASE_DIR}/dev"
  sudo mount --bind /dev "${BASE_DIR}/dev"
  mkdir -v "${BASE_DIR}/etc"
  sudo mount --bind /etc "${BASE_DIR}/etc"
  mkdir -v "${BASE_DIR}/opt"
  sudo mount --bind /opt "${BASE_DIR}/opt"
  mkdir -v "${BASE_DIR}/proc"
  sudo mount --bind /proc "${BASE_DIR}/proc"
  mkdir -v "${BASE_DIR}/root"
  sudo mount --bind /root "${BASE_DIR}/root"
  mkdir -v "${BASE_DIR}/run"
  sudo mount --bind /run "${BASE_DIR}/run"
  mkdir -v "${BASE_DIR}/home"
  sudo mount --bind /home "${BASE_DIR}/home"

  if [[ -d "/tmpfs" ]]; then
    mkdir -v "${BASE_DIR}/tmpfs"
    sudo mount --bind /tmpfs "${BASE_DIR}/tmpfs"
  fi
}

setup_sys_overlay () {
  mkdir -pv "${BASE_DIR}/sys/class/tpm/tpm0"
  touch "${BASE_DIR}/sys/class/tpm/tpm0/caps"
}

setup_base
setup_mounts
setup_sys_overlay
