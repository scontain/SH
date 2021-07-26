#!/bin/bash

# OOT
export OOT_REPOSITORY="https://github.com/intel/linux-sgx-driver.git"

export OOT_METRICS_PATCH_CONTENT=$(cat patches/oot-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_METRICS_PATCH_VERSION=2

export OOT_PAGE0_PATCH_CONTENT=$(cat patches/oot-page0.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_PAGE0_PATCH_VERSION=1

export OOT_FSGSBASE_PATCH_CONTENT=$(cat patches/oot-fsgsbase.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_FSGSBASE_PATCH_VERSION=1

export OOT_VERSION_PATCH_CONTENT=$(cat patches/oot-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_DKMS_PATCH_CONTENT=$(cat patches/oot-dkms.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_COMMIT_SHA="2d2b795890c01069aab21d4cdfd1226f7f65b971"

# DCAP
export DCAP_REPOSITORY="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"

export DCAP_METRICS_PATCH_CONTENT=$(cat patches/dcap-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_METRICS_PATCH_VERSION=1

export DCAP_FSGSBASE_PATCH_CONTENT=$(cat patches/dcap-fsgsbase.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_FSGSBASE_PATCH_VERSION=1

export DCAP_VERSION_PATCH_CONTENT=$(cat patches/dcap-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_COMMIT_SHA="30fac05232e13eab72c425a7788fafa5a46b3247"

echo -n "INFO: Creating install_sgx_driver.sh... "
envsubst < install_sgx_driver.tmpl '\
    ${OOT_REPOSITORY},\
    ${OOT_METRICS_PATCH_CONTENT},\
    ${OOT_METRICS_PATCH_VERSION},\
    ${OOT_PAGE0_PATCH_CONTENT},\
    ${OOT_PAGE0_PATCH_VERSION},\
    ${OOT_VERSION_PATCH_CONTENT},\
    ${OOT_DKMS_PATCH_CONTENT},\
    ${OOT_FSGSBASE_PATCH_CONTENT},\
    ${OOT_FSGSBASE_PATCH_VERSION},\
    ${DCAP_REPOSITORY},\
    ${DCAP_METRICS_PATCH_CONTENT},\
    ${DCAP_METRICS_PATCH_VERSION},\
    ${DCAP_FSGSBASE_PATCH_CONTENT},\
    ${DCAP_FSGSBASE_PATCH_VERSION},\
    ${DCAP_VERSION_PATCH_CONTENT},\
    ${OOT_COMMIT_SHA},\
    ${DCAP_COMMIT_SHA},\
    ' > install_sgx_driver.sh

echo "Done!"
