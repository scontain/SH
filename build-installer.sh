#!/bin/bash

export METRICS_PATCH_CONTENT=$(cat patches/metrics.patch | sed 's/\\$/\\@!-tbs-!@/g')
export PAGE0_PATCH_CONTENT=$(cat patches/page0.patch | sed 's/\\$/\\@!-tbs-!@/g')
export VERSION_PATCH_CONTENT=$(cat patches/version.patch | sed 's/\\$/\\@!-tbs-!@/g')
export COMMIT_SHA="95eaa6f6693cd86c35e10a22b4f8e483373c987c"

echo -n "INFO: Creating install_sgx_driver.sh... "
envsubst < install_sgx_driver.tmpl '${METRICS_PATCH_CONTENT},${VERSION_PATCH_CONTENT},${PAGE0_PATCH_CONTENT},${COMMIT_SHA}' > install_sgx_driver.sh
echo "Done!"
