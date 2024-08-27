# TODO

- [x] cvefixes extractor code into dict
- [x] govulndb extractor
- [x] nvddb extractor
- [x] cvefixes + govulndb combine script
- [x] nvd schema
- [x] osv schema
- [x] nvd fetcher using json script
- [x] govulns to json
- [x] cvefixes + govulns to json
- [x] get cve info using all 3 sources
- [x] validate osv script
- [x] dump and checkin
- [x] get filechanges using cvefixes in script
- [x] repo url list from cves
- [x] github extractor
- [x] per repo, gather repo metadata -> check for bulk apis
- [x] save repo metadata in repos section of cveinfo and overwrite if option
- [x] get associated commits one by one
- [x] calculate commits metadata and add in cveinfo
- [x] create file changes and method changes in filechanges json

- [x] Views of the dataset to evaluate
  - [x] The view should contain cveID, cwe, fixes, tokens
  - [x] Create multiple useful views based on different samples, but the view should be consistent
  - [x] Ideally the view should be created and stored in a json file so that it can be read and processed deterministically each time
  - [x] Dataset needs to be balanced
  - [x] Ideally some token metrics info related to the dataset needs to be present to do a dry run wrt cost of the dataset run
