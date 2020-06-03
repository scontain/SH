#!/bin/bash

patches="version metrics page0"

installer_url="https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh"
driver_repository="https://github.com/intel/linux-sgx-driver.git"

function download_installer {
    echo -n "INFO: Downlading installer from $installer_url... "
    installer_content=$(curl -fsSL $installer_url)
    echo "Done!"
}

function prepare_args {
    echo $1 |\
    sed 's/dcap/--dcap/g' |\
    sed 's/version/-p version/g' |\
    sed 's/metrics/-p metrics/g' |\
    sed 's/page0/-p page0/g'
}

function check_commit_sha {
    script_commit_sha=$(echo "$installer_content" | grep "driver_commit=" | cut -d'=' -f2 | sed 's/"//g')
    master_commit_sha=$(git ls-remote https://github.com/intel/linux-sgx-driver.git refs/heads/master | awk '{ print $1 }')

    if [[ $script_commit_sha != $master_commit_sha ]]; then
        echo "FAIL: Installer commit stamp differs from repository one. Please, update the installer."
        echo "[installer = $script_commit_sha; remote = $master_commit_sha]"

        exit 1
    fi
}

function combine {
    local limit=$[ 1 << $# ]
    local args=($@)
    for ((value = 1; value < limit; value++)); do
        local parts=()
        for ((i = 0; i < $#; i++)); do
            [ $[(1 << i) & value] -ne 0 ] && parts[${#parts[@]}]="${args[i]}"
        done
        echo "${parts[@]}"
    done
}

download_installer
check_commit_sha

# test the script with different arguments
while read -r line
do
    args=$(prepare_args "$line")

    echo "INFO: Running with arguments: install --force $args"
    echo "$installer_content" | bash -s - install --force $args

    ret=$?

    if [ $ret != 0 ]; then
        echo "FAIL: The installer failed with arguments: install --force $args"
        exit $ret
    fi
done < <(combine $patches)
