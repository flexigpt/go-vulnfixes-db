import gzip
import json
import os
from typing import Any

from pydantic import BaseModel


# Function to generate a unique file path if file already exists
def get_unique_filepath(filepath: str, overwrite: bool) -> str:
    if overwrite:
        return filepath
    base, extension = os.path.splitext(filepath)
    counter = 1
    unique_filepath = filepath
    while os.path.exists(unique_filepath):
        unique_filepath = f"{base}_{counter}{extension}"
        counter += 1
    return unique_filepath


def write_json(fpath: str, obj: Any):
    # Write the OSV schema to the output file
    with open(fpath, 'w', encoding='utf-8') as file:
        json.dump(obj, file, indent=2, ensure_ascii=False)


def read_json(fpath: str) -> Any:
    # Write the OSV schema to the output file
    with open(fpath, 'r', encoding='utf-8') as file:
        return json.load(file)


def write_pydantic_to_json(file_path: str, pydantic_obj: BaseModel):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(pydantic_obj.model_dump_json(indent=2, exclude_none=True))


def write_json_zip(fpath: str, obj: Any):
    # Write the JSON object to a gzip file
    with gzip.open(fpath, 'wt', encoding='utf-8') as gzfile:
        json.dump(obj, gzfile, indent=2, ensure_ascii=False)
