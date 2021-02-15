# Helper script to install Intel SGX driver

## Usage

```
Usage: install_sgx_driver.sh [COMMAND] [OPTIONS]...
Helper script to install Intel SGX driver.

The script supports the following commands:
  check                checks the current SGX driver status
                       (requires 'version' patch)
  install              installs the SGX driver

The following options are supported by 'install' command:
  -d, --dcap           installs the DCAP driver

  -a, --auto           select the driver according to the machine capabilities (DCAP or OOT)

  -p, --patch=[PATCH]  apply patches to the SGX driver. The valid values for PATCH
                       are: 'version', 'metrics', 'page0'.
      -p version       installs the version patch (recommended)
      -p metrics       installs the metrics patch
      -p page0         installs the page0 patch (not available for DCAP)

  -k, --dkms           installs the driver with DKMS (default for DCAP)

  -l, --latest         installs the latest upstream driver (not recommended)

  -f, --force          replaces existing SGX driver, if installed

The following options are supported by 'check' command:
  -p, --patch=[PATCH]  check the status of patch on current installed driver.
                       The valid values for PATCH are: 'metrics', 'page0'.
      -p metrics       check the status of 'metrics' patch
      -p page0         check the status of 'page0' patch (not available for DCAP)

Note: In case of absence or outdated driver, or absence or outdated patch, this command
will return error.

The following options are supported by both commands:
  -h, --help           display this help and exit
```

## Usage examples

### To install the driver with both `metrics` and `page0` patch, run:

```bash
$ curl -fsSL https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh | bash -s - install -p metrics -p page0
```

### To check the status of driver installation and 'metrics' patch, run:

```bash
$ curl -fsSL https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh | bash -s - check -p metrics
```

### To check whether it is necessary to create and update the patches, run:
```bash
$ ./run_ci.sh
```
