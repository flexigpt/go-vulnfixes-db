import logging
import sys


def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Set the log format
        stream=sys.stdout  # Set the stream to stdout
    )


configure_logging()
logger = logging.getLogger(__name__)
