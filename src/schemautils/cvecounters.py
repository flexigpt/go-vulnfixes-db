from typing import Set

from ..logging.logging import logger


def compare_cve_sets(cve_ids: Set[str], cves_from_fixesdb: Set[str]) -> None:
    """
    Compare two sets of CVE IDs and log the length of their intersection,
    the number of unique items in the first set, and the number of unique items in the second set.

    Parameters:
    - cve_ids: Set[str] - The set of CVE IDs from govulndb.
    - cves_from_fixesdb: Set[str] - The set of CVE IDs from cvefixes.
    """
    intersection = cve_ids.intersection(cves_from_fixesdb)
    only_in_cve_ids = cve_ids - cves_from_fixesdb
    only_in_cves_from_fixesdb = cves_from_fixesdb - cve_ids

    logger.info("Total cve ids found in GoVulnDB are %s", len(cve_ids))
    logger.info("Total cve ids found in CVEFixesDB are %s", len(cves_from_fixesdb))
    logger.info("CVEs in both DBs: %s", len(intersection))
    logger.info("Number of items only in GoVulnDB: %s", len(only_in_cve_ids))
    logger.info("Number of items only in CVEFixesDB: %s", len(only_in_cves_from_fixesdb))
