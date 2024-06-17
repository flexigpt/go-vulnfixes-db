import sqlite3
from typing import Dict, List, Tuple

from ...logging.logging import logger


def fetch_cve_language_data(db_path: str) -> List[Tuple[str, str]]:
    """
    Fetch CVE IDs and associated programming languages from the database.

    Parameters:
    - db_path: str - The path to the SQLite database file.

    Returns:
    - List[Tuple[str, str]] - A list of tuples containing CVE IDs and associated programming languages.
    """
    query = """
    SELECT f.cve_id, LOWER(fc.programming_language) AS lang
    FROM fixes f
    JOIN file_change fc ON f.hash = fc.hash
    WHERE fc.programming_language IS NOT NULL
    AND fc.programming_language != ''
    """

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error("An error occurred: %s", e)
        return []


def create_cve_language_dict(cve_lang_data: List[Tuple[str, str]]) -> Dict[str, Dict[str, int]]:
    """
    Create a dictionary with CVE IDs as keys and their associated programming languages and counts as values.

    Parameters:
    - cve_lang_data: List[Tuple[str, str]] - A list of tuples containing CVE IDs and associated programming languages.

    Returns:
    - Dict[str, Dict[str, int]] - A dictionary with CVE IDs as keys and another dictionary of programming languages and their counts as values.
    """
    cve_lang_dict = {}
    for cve_id, lang in cve_lang_data:
        if cve_id not in cve_lang_dict:
            cve_lang_dict[cve_id] = {}
        if lang in cve_lang_dict[cve_id]:
            cve_lang_dict[cve_id][lang] += 1
        else:
            cve_lang_dict[cve_id][lang] = 1
    return cve_lang_dict


def get_top_languages(lang_count: Dict[str, int], top_n: int = 1) -> List[str]:
    """
    Get the top N programming languages by count.

    Parameters:
    - lang_count: Dict[str, int] - A dictionary with programming languages as keys and their counts as values.
    - top_n: int - The number of top programming languages to return.

    Returns:
    - List[str] - A list of top N programming languages.
    """
    sorted_langs = sorted(lang_count.items(), key=lambda item: item[1], reverse=True)
    return [lang for lang, _ in sorted_langs[:top_n]]


def filter_cve_ids_by_languages(cve_lang_dict: Dict[str, Dict[str, int]], input_languages: List[str]) -> List[str]:
    """
    Filter CVE IDs based on the input languages being among the top languages.

    Parameters:
    - cve_lang_dict: Dict[str, Dict[str, int]] - A dictionary with CVE IDs as keys and another dictionary of programming languages and their counts as values.
    - input_languages: List[str] - A list of programming languages to filter by.

    Returns:
    - List[str] - A list of filtered CVE IDs.
    """
    input_languages_lower = [lang.lower() for lang in input_languages]
    filtered_cve_ids = []

    for cve_id, lang_count in cve_lang_dict.items():
        top_languages = get_top_languages(lang_count)
        if any(lang in top_languages for lang in input_languages_lower):
            filtered_cve_ids.append(cve_id)

    return filtered_cve_ids


def get_cve_ids_by_languages(db_path: str, languages: List[str]) -> Tuple[List[str], List[Tuple[str, int]]]:
    """
    Retrieve all CVE IDs belonging to a given list of programming languages (case-insensitive)
    and their counts, and return the top 2 programming languages.

    Parameters:
    - db_path: str - The path to the SQLite database file.
    - languages: List[str] - A list of programming languages to filter by.

    Returns:
    - Tuple[List[str], List[Tuple[str, int]]] - A tuple containing a list of CVE IDs that match
      the given programming languages and a list of tuples with programming languages and their counts.
    """
    cve_lang_data = fetch_cve_language_data(db_path)
    cve_lang_dict = create_cve_language_dict(cve_lang_data)
    filtered_cve_ids = filter_cve_ids_by_languages(cve_lang_dict, languages)

    # For debugging: Output the language counts for each CVE ID
    cve_lang_counts = [(cve_id, list(lang_count.items())) for cve_id, lang_count in cve_lang_dict.items()]

    return filtered_cve_ids, cve_lang_counts


def get_all_cve_ids(db_path: str) -> List[str]:
    cve_ids: List[str] = []

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Query to get all CVE IDs from the cve table
        cursor.execute("SELECT cve_id FROM cve")
        rows = cursor.fetchall()

        # Extract CVE IDs from the query result
        cve_ids = [row[0] for row in rows]

    return cve_ids


def create_index_if_not_exists(cursor, index_name, table_name, column_name):
    # Check if the index already exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index_name, ))
    index_exists = cursor.fetchone()

    # Create the index if it does not exist
    if not index_exists:
        cursor.execute(f"CREATE INDEX {index_name} ON {table_name} ({column_name})")


def ensure_indexes(db_path: str):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Create indexes for performance improvement
        create_index_if_not_exists(cursor, 'idx_cve_id', 'cve', 'cve_id')
        create_index_if_not_exists(cursor, 'idx_fixes_cve_id', 'fixes', 'cve_id')
        create_index_if_not_exists(cursor, 'idx_fixes_hash', 'fixes', 'hash')
        create_index_if_not_exists(cursor, 'idx_file_change_hash', 'file_change', 'hash')
        create_index_if_not_exists(cursor, 'idx_file_change_id', 'file_change', 'file_change_id')
        create_index_if_not_exists(cursor, 'idx_method_change_file_change_id', 'method_change', 'file_change_id')

        conn.commit()
