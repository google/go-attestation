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
# Stops the TPM 1.2 simulator + trousers from running.
# USAGE: ./shutdown_tpm12_simulator.sh <working dir>
set -e

if [[ "${1}" == "" ]]; then
  >&2 echo "Error: Must specify the working directory as the first argument."
  exit 1
fi

BUILD_BASE="${1%/}" # Trim any trailing slash.

sudo kill $(cat "${BUILD_BASE}/tcsd_pid")
rm "${BUILD_BASE}/tcsd_pid"
sudo kill $(cat "${BUILD_BASE}/sim_pid")
rm "${BUILD_BASE}/sim_pid"
