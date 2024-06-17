import ast
import json
import re
from typing import Any

from ...logging.logging import logger


def convert_pandas_str_to_json(json_str_orig: str) -> Any:
    try:
        # First attempt to decode the JSON string directly
        return json.loads(json_str_orig)
    except json.JSONDecodeError:
        try:
            # Step 1: Attempt to use ast.literal_eval to parse the string
            try:
                # Convert the JSON-like string into a Python literal
                parsed_data = ast.literal_eval(json_str_orig)
                # Convert the Python literal back to a JSON string and then parse it
                json_str = json.dumps(parsed_data)
                return json.loads(json_str)
            except (ValueError, SyntaxError) as e:
                logger.error("Failed to evaluate string with ast.literal_eval: %s", e)

            # If ast.literal_eval fails, perform manual cleaning

            json_str = json_str_orig

            # Step 2: Remove single quotes inside double-quoted strings
            json_str = re.sub(r'(?<!\\)"(.*?)(?<!\\)\'(.*?)(?<!\\)"', lambda m: f'"{m.group(1)}{m.group(2)}"', json_str)

            # Step 3: Remove double quotes inside double-quoted strings
            json_str = re.sub(r'(?<!\\)"(.*?)(?<!\\)"(.*?)(?<!\\)"', lambda m: f'"{m.group(1)}{m.group(2)}"', json_str)

            # Step 4: Remove double quotes inside single-quoted strings
            json_str = re.sub(r"(?<!\\)'(.*?)(?<!\\)\"(.*?)(?<!\\)'", lambda m: f"'{m.group(1)}{m.group(2)}'", json_str)

            # Step 5: Replace single quotes with double quotes
            json_str = json_str.replace("'", '"')

            # Step 6: Replace True/False with true/false
            json_str = json_str.replace("True", "true").replace("False", "false")

            # Step 7: Attempt to decode the cleaned string as JSON
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error("Failed to decode JSON after cleaning: %s", e)
            logger.error("Original string: %s", json_str_orig)
            logger.error("String after processing: %s", json_str)
            raise
