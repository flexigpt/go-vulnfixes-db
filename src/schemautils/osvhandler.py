# import json
from typing import Dict, List

from packaging.version import Version

# from ..logging.logging import logger
from ..schemas import osv


def merge_refs(ref1: List[Dict[str, str]], ref2: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    Merges two arrays of references based on their URLs.
    If a URL from ref1 exists in ref2, the type from ref2 is used.
    Otherwise, the item from ref1 is added as is.
    Any URLs in ref2 that are not in ref1 are also added.

    Parameters:
    ref1 (list): The first list of references, each containing a 'type' and 'url'.
    ref2 (list): The second list of references, each containing a 'type' and 'url'.

    Returns:
    list: A new array of merged references.
    """
    # Create a dictionary from the second array for quick lookup
    url_to_type_map = {item['url']: item['type'] for item in ref2}

    new_array = []

    # Iterate through the first array
    for item in ref1:
        url = item['url']
        if url in url_to_type_map:
            # If URL is in second array, use the type from the second array
            new_array.append({'url': url, 'type': url_to_type_map[url]})
        else:
            # If URL is not in second array, add it to the new array
            new_array.append(item)

    # Add items from the second array that are not in the first array
    ref1_urls = set(item['url'] for item in ref1)
    for item in ref2:
        if item['url'] not in ref1_urls:
            new_array.append(item)

    return new_array


def merge_severity(osv1: osv.OpenSourceVulnerability, osv2: osv.OpenSourceVulnerability) -> List[osv.SeverityItem]:
    severity_dict = {}

    if osv1.severity:
        for item in osv1.severity:
            severity_dict[item.type] = item

    if osv2.severity:
        for item in osv2.severity:
            if item.type not in severity_dict:
                severity_dict[item.type] = item

    return list(severity_dict.values())


def merge_osv_schemas(osv1: osv.OpenSourceVulnerability,
                      osv2: osv.OpenSourceVulnerability) -> osv.OpenSourceVulnerability:
    """
    Merges two OpenSourceVulnerability schemas into a single schema.

    Parameters:
    osv1 (osv.OpenSourceVulnerability): The first OSV schema.
    osv2 (osv.OpenSourceVulnerability): The second OSV schema.

    Returns:
    osv.OpenSourceVulnerability: The merged OSV schema.
    """
    # Merge aliases
    aliases = list(set(osv1.aliases or []) | set(osv2.aliases or []))
    if osv1.id and osv1.id in aliases:
        aliases.remove(osv1.id)
    elif osv2.id and osv2.id in aliases:
        aliases.remove(osv2.id)

    # Merge related
    related = list(set(osv1.related or []) | set(osv2.related or []))

    # Merge summary
    summary = f"{osv1.summary or ''}. {osv2.summary or ''}".strip('. ')

    # Merge details
    details = f"{osv1.details or ''}. {osv2.details or ''}".strip('. ')

    # Merge credits
    credits_data = (osv1.credits or []) + (osv2.credits or [])

    # Merge severity if present
    severity = merge_severity(osv1, osv2)

    # Merge database_specific into a dict. osv1 keys will overwrite anything from osv2
    database_specific_dict = {
        **(osv2.database_specific.model_dump(exclude_none=True) if osv2.database_specific else {}),
        **(osv1.database_specific.model_dump(exclude_none=True) if osv1.database_specific else {}),
    }
    # logger.info(json.dumps(database_specific_dict, indent=2))

    ref1_list = [ref.model_dump() for ref in (osv1.references or [])]
    ref2_list = [ref.model_dump() for ref in (osv2.references or [])]
    references_list = merge_refs(ref1_list, ref2_list)
    references = None
    if references_list:
        references = [osv.ReferenceItem(**ref_dict) for ref_dict in references_list]

    # Overwrite affected using affected from osv2
    affected = osv2.affected if osv2.affected else osv1.affected

    return osv.OpenSourceVulnerability(
        # prefer schema version from first
        schema_version=osv1.schema_version
        if Version(osv1.schema_version) > Version(osv2.schema_version) else osv2.schema_version,
        # prefer id from first
        id=osv1.id or osv2.id,
        # prefer modified from first
        modified=osv1.modified or osv2.modified,
        # prefer published from first
        published=osv1.published or osv2.published,
        # prefer withdrawn from first
        withdrawn=osv1.withdrawn or osv2.withdrawn,
        aliases=aliases,
        related=related,
        summary=summary,
        details=details,
        severity=severity,
        affected=affected,
        references=references,
        credits=credits_data,
        database_specific=osv.TopDatabaseSpecificModel(**database_specific_dict))
