# go-vulnfixes-db

Dataset for Golang featuring vulnerable code and corresponding fixes, covering both CVE-based and synthetic issues

## CVEInfo

- CVE info is taken from [NVD](https://nvd.nist.gov/developers/vulnerabilities), [Golang vuln db](https://go.dev/doc/security/vuln/database) and [CVEFixes dataset](https://zenodo.org/records/7029359)
- The schema of the dataset is compatible with [OSV schema specification](https://ossf.github.io/osv-schema/).
- The unified vulnerability file adds NVD metrics, repository info and commits info.
- The Python representation of the schema can be seen [here](./src/schemas/osv.py).

- The CVEs generated for all extracted vulnerabilities is present [here](./data/go-cves)
- The original Go vulnerability db files are uploaded [here](./externaldata/govulndb/)
- The NVD vulnerability db files are uploaded [here](./externaldata/nvd/)

- Last update time of Go VulnDB: June 10 2024

## FixesInfo

- File changes are taken from CVEFixes dataset or direct git pull through references in CVEInfo
- A few change sets those are very large (>4MB) are dropped. This number is very small for now (<5)
- The zipped changes files are present [here](./data/go-fixes/)

## Initializing the repo

- Checkout the repository
- Create a venv
- Activate the venv and install `pip-tools`
- `pip-compile requirements.in -o requirements.txt`
- For upgrading dependencies, add `--upgrade` to above
