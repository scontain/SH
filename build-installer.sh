#!/bin/bash

# OOT
export OOT_REPOSITORY="https://github.com/intel/linux-sgx-driver.git"

export OOT_METRICS_PATCH_CONTENT=$(cat patches/oot-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_METRICS_PATCH_VERSION=2

export OOT_PAGE0_PATCH_CONTENT=$(cat patches/oot-page0.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_PAGE0_PATCH_VERSION=1

export OOT_VERSION_PATCH_CONTENT=$(cat patches/oot-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_DKMS_PATCH_CONTENT=$(cat patches/oot-dkms.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_COMMIT_SHA="b0a445ba09e96e1d0507487e5c496485a9cf3742"

# DCAP
export DCAP_REPOSITORY="https://github.com/intel/SGXDataCenterAttestationPrimitives.git"

export DCAP_METRICS_PATCH_CONTENT=$(cat patches/dcap-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_METRICS_PATCH_VERSION=1

export DCAP_VERSION_PATCH_CONTENT=$(cat patches/dcap-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_COMMIT_SHA="c9b707408d14fc1f1dcc519950bafb8bc58f0f42"

echo -n "INFO: Creating install_sgx_driver.sh... "
envsubst < install_sgx_driver.tmpl '\
    ${OOT_REPOSITORY},\
    ${OOT_METRICS_PATCH_CONTENT},\
    ${OOT_METRICS_PATCH_VERSION},\
    ${OOT_PAGE0_PATCH_CONTENT},\
    ${OOT_PAGE0_PATCH_VERSION},\
    ${OOT_VERSION_PATCH_CONTENT},\
    ${OOT_DKMS_PATCH_CONTENT},\
    ${DCAP_REPOSITORY},\
    ${DCAP_METRICS_PATCH_CONTENT},\
    ${DCAP_METRICS_PATCH_VERSION},\
    ${DCAP_VERSION_PATCH_CONTENT},\
    ${OOT_COMMIT_SHA},\
    ${DCAP_COMMIT_SHA},\
    ' > install_sgx_driver.sh

echo "Done!"
