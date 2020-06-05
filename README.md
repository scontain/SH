# SH

Helper script to install Intel SGX driver.

## Usage

```
Usage: install_sgx_driver.sh [COMMAND] [OPTIONS]...
Helper script to install Intel SGX driver.

The script supports the following commands:
  install              installs the SGX driver

The following options are supported:
  -d, --dcap           install DCAP driver

  -p, --patch=[PATCH]  apply patches to the SGX driver. The valid values for PATCH
                       are: 'version', 'metrics', 'page0'.
      -p version       installs the version patch
      -p metrics       installs the metrics patch
      -p page0         installs the page0 patch (not available for DCAP)

  -l, --latest         installs the latest upstream driver (not recommended)

  -f, --force          replaces existing SGX driver, if installed
  -h, --help           display this help and exit
```

For example, to install the driver with both `metrics` and `page0` patch, run:

```bash
$ curl -fsSL https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh | bash -s - install -p metrics -p page0
```
