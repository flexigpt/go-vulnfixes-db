# go-vulnfixes-db <!-- omit in toc -->

Dataset for Golang featuring vulnerable code and corresponding fixes (i.e commit code), covering both CVE-based and synthetic issues. CWE based categorizations are also present.

- [CVE Metadata Info](#cve-metadata-info)
  - [Sources](#sources)
  - [Dataset representation](#dataset-representation)
- [CVE FixesInfo](#cve-fixesinfo)
- [CWE Info](#cwe-info)
- [Views](#views)
- [Initializing the repo](#initializing-the-repo)

## CVE Metadata Info

### Sources

- CVE info is taken from [NVD](https://nvd.nist.gov/developers/vulnerabilities), [Golang vuln db](https://go.dev/doc/security/vuln/database) and [CVEFixes dataset](https://zenodo.org/records/7029359)
- The schema of the dataset is compatible with [OSV schema specification](https://ossf.github.io/osv-schema/).
- The unified vulnerability file adds NVD metrics, repository info and commits info.
- Last update time of Go VulnDB: June 10 2024

### Dataset representation

- The Python representation of the schema can be seen [here](./src/schemas/osv.py).
- The CVEs generated for all extracted vulnerabilities is present [here](./data/go-cves)
- The original Go vulnerability db files are uploaded [here](./externaldata/govulndb/)
- The NVD vulnerability db files are uploaded [here](./externaldata/nvd/)

## CVE FixesInfo

- File changes are taken from CVEFixes dataset or direct git pull through references in CVEInfo
- A few change sets those are very large (>4MB) are dropped. This number is very small for now (<5)
- The zipped changes files are present [here](./data/go-fixes/)

## CWE Info

- All info collected for base CWEs under software development (i.e [CWE-699](https://cwe.mitre.org/data/definitions/699.html)) are present [here](./data/cwe-699).
- The CWE info present from the MITRE database is enriched for adding functional primary and secondary categorizations. This is done using `GPT-4o`.
- The final categorized list is present [here](./data/cwe-699/cwe_functional_areas.json)
- A few top n lists defined by MITRE are also present [here](./data/cwe-699/)

## Views

- A few views are created for analysis purposes and added [here](./data/views/)

## Initializing the repo

- Checkout the repository
- Make sure you have poetry installed as described [here](https://python-poetry.org/docs/#installation)
- cd to the repository and do `poetry install`
