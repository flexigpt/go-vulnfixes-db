import logging
import os
import sys


def configure_logging():
    level_str = os.getenv("LOG_LEVEL")
    if level_str == "debug":
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Set the log format
        stream=sys.stdout  # Set the stream to stdout
    )


configure_logging()
logger = logging.getLogger(__name__)
