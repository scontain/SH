# SH

Helper script to install Intel SGX driver.

## Usage

```
Usage: install_sgx_driver.sh [OPTION]...
Helper script to install Intel SGX driver.

The script supports the following commands:
  help     display this help and exit
  install  installs the current Intel out of branch driver if not SGX driver is installed
      -p metrics      installs the metrics patch
      -p page0        installs the page0 patch
  force   same as 'install' but will replace existing SGX driver (if installed)
```

For example, to install the driver with both `metrics` and `page0` patch, run:

```bash
$ curl -fsSL https://raw.githubusercontent.com/scontain/SH/master/install_sgx_driver.sh | bash -s - install -p metrics -p page0
```
