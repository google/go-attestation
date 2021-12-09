#!/bin/bash -e

1>&2 echo "-----
WARNING: The TPM 1.2 simulator no longer builds with newer versions of openssl.
These scripts are kept for posterity, but likely won't build on new OS
versions.
----"

export PROJECT_ROOT="$( pwd )"
TMPDIR="$( mktemp -d )"
SIM_DIR="${TMPDIR}/tpm12_sim"

TEST_ROOT="${TMPDIR}/tests_base"

mkdir -pv "${SIM_DIR}"
./ci/setup_tpm12_simulator.sh "${SIM_DIR}"
./ci/setup_tests_fs.sh "${TEST_ROOT}"

go test -v ./... -- --testTPM12

./ci/shutdown_tpm12_simulator.sh "${SIM_DIR}"
