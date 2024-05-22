"""Mapping threat data to the required format for processing."""

import inspect
from ..SharedCode import consts
from ..SharedCode.logger import applogger
from ..SharedCode.infoblox_exception import InfobloxException


class Mapping:
    """Mapping class to map threat data to the required format for processing."""

    def __init__(self):
        """Initialize instance variable for class."""
        self.confidence = consts.CONFIDENCE_THRESHOLD
        self.threat_level = consts.THREAT_LEVEL

    def map_threat_data(self, item_list):
        """Map threat data to the required format for processing.

        Args:
            item_list (list): A list of threat data items to be processed.

        Returns:
            list: A list of mapped threat data items in the required format.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    consts.INDICATOR_FUNCTION_NAME,
                    "Mapping threat data, No. of files to map = {}".format(len(item_list)),
                )
            )
            mapped = []
            temp = {
                "HOST": "[domain-name:value = '{}']",
                "IP": "[ipv4-addr:value = '{}']",
                "URL": "[url:value = '{}']",
                "HASH": "[file:value = '{}']",
                "EMAIL": "{}",
            }
            for item in item_list:
                confidence_val = item.get("confidence", 0)
                threat_level_val = item.get("threat_level", 0)
                if threat_level_val >= self.threat_level and (
                    self.confidence == 0 or confidence_val >= self.confidence
                ):
                    body = {
                        "name": "Infoblox - {} - {}".format(item.get("type"), item.get("id")),
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": "indicator--{}".format(item.get("id")),
                        "created": item.get("detected"),
                        "modified": item.get("detected"),
                        "revoked": item.get("up", False),
                        "labels": [
                            item.get("type"),
                            "Imported : {}".format(item.get("imported")),
                            "Profile : {}".format(item.get("profile")),
                            "Property : {}".format(item.get("property")),
                            "Threat Level : {}".format(item.get("threat_level")),
                        ],
                        "confidence": (item.get("confidence", 0)),
                        "description": "Infoblox - {} - {}".format(item.get("type"), item.get("class")),
                        "indicator_types": [item.get("class")],
                        "pattern": temp.get(item.get("type")).format(item.get(item.get("type").lower())),
                        "pattern_type": "stix",
                        "pattern_version": "2.1",
                        "valid_from": item.get("received"),
                        "valid_until": item.get("expiration"),
                    }
                    mapped.append(body)
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    consts.INDICATOR_FUNCTION_NAME,
                    "No. of files after mapping = {}".format(len(mapped)),
                )
            )
            return mapped
        except KeyError as keyerror:
            applogger.error(
                "{} : {} (method={}), KeyError while mapping threat data :{}".format(
                    consts.LOGS_STARTS_WITH,
                    consts.INDICATOR_FUNCTION_NAME,
                    __method_name,
                    keyerror,
                )
            )
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                "{} : {} (method={}), Error while mapping threat data :{}".format(
                    consts.LOGS_STARTS_WITH,
                    consts.INDICATOR_FUNCTION_NAME,
                    __method_name,
                    error,
                )
            )
            raise InfobloxException()

    def create_chunks(self, text, start_index):
        """Create chunk from text starting at a specific index.

        Args:
            text (str): The input text from which chunks will be created.
            start_index (int): The starting index to begin creating chunks from.

        Returns:
            list: A list of chunked data items.

        Raises:
            InfobloxException: If an error occurs while breaking the data into chunks.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    consts.INDICATOR_FUNCTION_NAME,
                    "Creating Chunks",
                )
            )
            chunk_size = consts.CHUNK_SIZE
            chunked_data = [text[index : index + chunk_size] for index in range(start_index, len(text), chunk_size)]
            applogger.info(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    consts.INDICATOR_FUNCTION_NAME,
                    "Number of chunks : {}".format(len(chunked_data)),
                )
            )
            return chunked_data
        except Exception as error:
            applogger.error(
                consts.LOG_FORMAT.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    consts.INDICATOR_FUNCTION_NAME,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()
