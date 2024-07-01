import json
import sys

import xmltodict


def convert_xml_to_json(xml_file, json_file):
    try:
        with open(xml_file, 'r') as file:
            xml_content = file.read()
        xml_dict = xmltodict.parse(xml_content)
        json_content = json.dumps(xml_dict, indent=4)
        with open(json_file, 'w') as file:
            file.write(json_content)
        print(f"Successfully converted {xml_file} to {json_file}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python xml_to_json.py <input.xml> <output.json>")
        sys.exit(1)
    xml_file = sys.argv[1]
    json_file = sys.argv[2]
    convert_xml_to_json(xml_file, json_file)
