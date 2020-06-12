#!/bin/bash

patches="version metrics page0 dcap"

installer_url="https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh"

function download_installer {
    echo -n "INFO: Downloading installer from $installer_url... "
    installer_content=$(curl -fsSL $installer_url)
    echo -e "Done!\n"
}

function prepare_args {
    echo $1 |\
    sed 's/dcap/--dcap/g' |\
    sed 's/version/-p version/g' |\
    sed 's/metrics/-p metrics/g' |\
    sed 's/page0/-p page0/g'
}

function check_commit_sha {
    echo -n "TEST: Verifying OOT driver commit stamp... "

    oot_script_commit_sha=$(echo "$installer_content" | grep "oot_driver_commit=" | cut -d'=' -f2 | sed 's/"//g')
    oot_master_commit_sha=$(git ls-remote https://github.com/intel/linux-sgx-driver.git refs/heads/master | awk '{ print $1 }')

    if [[ $oot_script_commit_sha != $oot_master_commit_sha ]]; then
        echo -e "\nFAIL: Installer OOT commit stamp differs from repository one. Please, update the installer."
        echo -e "[installer = $oot_script_commit_sha; remote = $oot_master_commit_sha]\n"

        check_commit_fail=1
    else
        echo "Done!"
    fi

    echo -n "TEST: Verifying DCAP driver commit stamp... "

    dcap_script_commit_sha=$(echo "$installer_content" | grep "dcap_driver_commit=" | cut -d'=' -f2 | sed 's/"//g')
    dcap_master_commit_sha=$(git ls-remote https://github.com/intel/SGXDataCenterAttestationPrimitives.git refs/heads/master | awk '{ print $1 }')

    if [[ $dcap_script_commit_sha != $dcap_master_commit_sha ]]; then
        echo -e "\nFAIL: Installer DCAP commit stamp differs from repository one. Please, update the installer."
        echo -e "[installer = $dcap_script_commit_sha; remote = $dcap_master_commit_sha]\n"

        check_commit_fail=1
    else
        echo "Done!"
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

if [[ $check_commit_fail == "1" ]]; then
    exit 1
fi

# test the script with different arguments
while read -r line
do
    args=$(prepare_args "$line")

    echo "TEST: Running the installer with arguments: install --force $args"
    echo "$installer_content" | bash -s - install --force $args

    ret=$?

    if [ $ret != 0 ]; then
        echo "FAIL: The installer failed with arguments: install --force $args"
        exit $ret
    fi
done < <(combine $patches)
