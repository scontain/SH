#!/bin/bash

# OOT
export OOT_METRICS_PATCH_CONTENT=$(cat patches/oot-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_PAGE0_PATCH_CONTENT=$(cat patches/oot-page0.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_VERSION_PATCH_CONTENT=$(cat patches/oot-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export OOT_COMMIT_SHA="95eaa6f6693cd86c35e10a22b4f8e483373c987c"

# DCAP
export DCAP_METRICS_PATCH_CONTENT=$(cat patches/dcap-metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_VERSION_PATCH_CONTENT=$(cat patches/dcap-version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export DCAP_COMMIT_SHA="bfa5d8f6935238c170324cac482b04650d2db4ac"

echo -n "INFO: Creating install_sgx_driver.sh... "
envsubst < install_sgx_driver.tmpl '\
    ${OOT_METRICS_PATCH_CONTENT},\
    ${OOT_VERSION_PATCH_CONTENT},\
    ${OOT_PAGE0_PATCH_CONTENT},\
    ${OOT_COMMIT_SHA},\
    ${DCAP_METRICS_PATCH_CONTENT},\
    ${DCAP_VERSION_PATCH_CONTENT},\
    ${DCAP_COMMIT_SHA},\
    ' > install_sgx_driver.sh

echo "Done!"
