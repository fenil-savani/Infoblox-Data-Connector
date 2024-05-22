"""Utils File."""

import inspect
import requests
import time
import json
import random
import datetime
from .state_manager import StateManager
from azure.storage.fileshare import ShareDirectoryClient
from azure.core.exceptions import ResourceNotFoundError
from .infoblox_exception import InfobloxException
from .logger import applogger
from . import consts
from .sentinel import post_data


class Utils:
    """Utils Class."""

    def __init__(self, azure_function_name) -> None:
        """Init Function."""
        self.azure_function_name = azure_function_name
        self.log_format = consts.LOG_FORMAT
        self.headers = {}

    def check_environment_var_exist(self, environment_var):
        """Check the existence of required environment variables.

        Logs the validation process and completion. Raises InfobloxException if any required field is missing.

        Args:
            environment_var(list) : variables to check for existence
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Validating Environment Variables",
                )
            )
            missing_required_field = False
            for i in environment_var:
                key, val = next(iter(i.items()))
                if (val is None) or (val == ""):
                    missing_required_field = True
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Environment variable {} is not set".format(key),
                        )
                    )
            if missing_required_field:
                applogger.error(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Validation failed",
                    )
                )
                raise InfobloxException()
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Validation Complete",
                )
            )
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def get_checkpoint_data(self, checkpoint_obj: StateManager, load_flag=False):
        """Get checkpoint data from a StateManager object.

        It retrieves the checkpoint data and logs it if the load flag is set to True.

        Args:
            checkpoint_obj (StateManager): The StateManager object to retrieve checkpoint data from.
            load_flag (bool): A flag indicating whether to load the data as JSON (default is False).

        Returns:
            The retrieved checkpoint data.

        Raises:
            InfobloxException: When an Infoblox related exception occurs.
            Exception: When any other exception occurs.

        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            checkpoint_data = checkpoint_obj.get()
            if load_flag and checkpoint_data:
                checkpoint_data = json.loads(checkpoint_data)
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Checkpoint fetch with json.loads",
                    )
                )
                return checkpoint_data
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Checkpoint fetch without json.loads",
                )
            )
            return checkpoint_data
        except json.decoder.JSONDecodeError as json_error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "JSONDecodeError error : Error-{}".format(json_error),
                )
            )
            raise InfobloxException()
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def post_checkpoint_data(self, checkpoint_obj: StateManager, data, dump_flag=False):
        """Post checkpoint data.

        It posts the data to a checkpoint object based on the dump_flag parameter.

        Args:
            checkpoint_obj (StateManager): The StateManager object to post data to.
            data: The data to be posted.
            dump_flag (bool): A flag indicating whether to dump the data as JSON before posting (default is False).

        Raises:
            TypeError: When a type error occurs.
            Exception: When any other exception occurs.
            InfobloxException: When an Infoblox related exception occurs.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            if dump_flag:
                applogger.debug(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Posting data = {}".format(data),
                    )
                )
                checkpoint_obj.post(json.dumps(data))
            else:
                applogger.debug(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Posting data with Len = {}".format(len(data)),
                    )
                )
                checkpoint_obj.post(data)
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Data posted to azure storage",
                )
            )
        except TypeError as type_error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Type error : Error-{}".format(type_error),
                )
            )
            raise InfobloxException()
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def list_file_names_in_file_share(self, parent_dir: ShareDirectoryClient, file_name_prefix):
        """Get list of file names from directory.

        Args:
            parent_dir (ShareDirectory.from_connection_string): Object of ShareDirectory to perform operations
            on file share.

        Returns:
            list: list of files
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            files_list = list(parent_dir.list_directories_and_files(file_name_prefix))
            file_names = []
            if (len(files_list)) > 0:
                for file in files_list:
                    file_names.append(file["name"])
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Retrieved files for prefix = {}, Total files = {}".format(
                        file_name_prefix,
                        len(file_names),
                    ),
                )
            )
            return file_names
        except ResourceNotFoundError:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "No storage directory found",
                )
            )
            return None
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def delete_files_from_azure_storage(self, files_list, parent_dir: ShareDirectoryClient):
        """Delete list of files.

        Args:
            files_list (list) : list of files to be deleted
            parent_dir (ShareDirectory.from_connection_string): Object of ShareDirectory to perform operations
            on file share.

        Returns:
            None
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            for file_path in files_list:
                parent_dir.delete_file(file_path)

            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Deleted files = {}".format(len(files_list)),
                )
            )
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def filter_file_list(self, file_prefix):
        """
        Filter a list of filenames based on a given file prefix.

        Args:
            file_prefix(str): A string representing the prefix of the filenames to filter.

        Returns:
            list: A list of filenames that are created before 10 minutes ago.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            parent_file = ShareDirectoryClient.from_connection_string(
                conn_str=consts.CONN_STRING,
                share_name=consts.FILE_SHARE_NAME_DATA,
                directory_path="",
            )

            filenames = self.list_file_names_in_file_share(parent_file, file_prefix)
            if filenames is None:
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "No files found",
                    )
                )
                return []
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Sort Files by current timestamp",
                )
            )
            sorted_filenames = sorted(filenames, key=lambda x: self.get_timestamp(x))

            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Filter files created before 15 mins.",
                )
            )
            current_time = int(time.time())

            filtered_filenames = [
                filename for filename in sorted_filenames if ((current_time - self.get_timestamp(filename)) > 900)
            ]
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Filtered File count = {}".format(len(filtered_filenames)),
                )
            )
            return filtered_filenames
        except InfobloxException:
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def get_timestamp(self, filename):
        """Get the timestamp from filename.

        Args:
            filename (str): The name of the file.

        Returns:
            int: The timestamp of the file.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            return int(filename.split("_")[5])
        except IndexError as index_error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Index error : Error-{}".format(index_error),
                )
            )
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def handle_failed_indicators(self, indicator_list, response_json):
        """Handle failed indicators by writing them to a new file or ingesting them into a log table.

        Args:
            indicator_list (list): List of indicators.
            response_json (dict): JSON response including errors.

        Raises:
            KeyError: If there is a key error while handling the indicators.
            InfobloxException: If an Infoblox-specific exception is raised.
            Exception: If any other general exception occurs.

        Returns:
            None
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            record_indexes = [error.get("recordIndex") for error in response_json["errors"]]
            failed_indicators = [indicator_list[index] for index in record_indexes]

            # LOGIC TO WRITE FAILED INDICATORS IN NEW FILE
            if self.azure_function_name == consts.INDICATOR_FUNCTION_NAME:
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Writing Failed Indicators to new file.",
                    )
                )
                file_timestamp = time.time()
                failed_file_name = "infoblox_failed_tide_indicators_file_{}".format(str(int(file_timestamp)))
                failed_indicator_file_obj = StateManager(
                    consts.CONN_STRING, failed_file_name, consts.FILE_SHARE_NAME_DATA
                )
                self.post_checkpoint_data(failed_indicator_file_obj, failed_indicators, dump_flag=True)
            elif self.azure_function_name == consts.FAILED_INDICATOR_FUNCTION_NAME:
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Ingesting Failed Indicators to Log Table.",
                    )
                )
                post_data(
                    body=json.dumps(failed_indicators),
                    log_type=consts.FAILED_INDICATORS_TABLE_NAME,
                )
        except KeyError as keyerror:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Key error : Error-{}".format(keyerror),
                )
            )
            raise InfobloxException()
        except InfobloxException:
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def auth_sentinel(self):
        """Authenticate with microsoft sentinel.

        This will return bearer token

        Args:
            None

        Returns:
            string: access token.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            for i in range(consts.MAX_RETRIES):
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Generating microsoft sentinel access token.",
                    )
                )
                azure_auth_url = consts.AZURE_AUTHENTICATION_URL.format(consts.AZURE_TENANT_ID)
                applogger.debug(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Calling auth url = {}".format(azure_auth_url),
                    )
                )
                body = {
                    "client_id": consts.AZURE_CLIENT_ID,
                    "client_secret": consts.AZURE_CLIENT_SECRET,
                    "grant_type": "client_credentials",
                    "scope": "https://management.azure.com/.default",
                }
                try:
                    response = requests.post(url=azure_auth_url, data=body)
                except requests.RequestException as error:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Request error : Error-{} Index = {}".format(error, i),
                        )
                    )
                    continue
                if response.status_code >= 200 and response.status_code <= 299:
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Got response with Status code : {}".format(response.status_code),
                        )
                    )
                    response_json = response.json()
                    bearer_token = self.get_bearer_token_from_response(response_json)
                    applogger.debug(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Bearer Token Generated: {}".format(bearer_token),
                        )
                    )
                    self.headers = {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(bearer_token),
                    }
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "MS authentication complete",
                        )
                    )
                    return
                elif response.status_code == 400:
                    response_json = response.json()
                    error = response_json.get("error", "Bad request")
                    error_description = response_json.get("error_description", "")
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Status Code = {}, Error-{}, Error Description = {}".format(
                                response.status_code,
                                error,
                                error_description,
                            ),
                        )
                    )
                    raise InfobloxException()
                elif response.status_code == 401:
                    response_json = response.json()
                    error = response_json.get("error", "Unauthorized")
                    error_description = response_json.get("error_description", "")
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Status Code = {}, Error-{}, Error Description = {}".format(
                                response.status_code,
                                error,
                                error_description,
                            ),
                        )
                    )
                    raise InfobloxException()
                elif response.status_code == 500:
                    log_message = "Internal Server Error"
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Status Code = {}, Error-{}".format(response.status_code, log_message),
                        )
                    )
                    raise InfobloxException()
                else:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Status Code = {}, Error-{}".format(response.status_code, response.content),
                        )
                    )
                    raise InfobloxException()
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Max retries reached for authentication of sentinel API",
                )
            )
            raise InfobloxException()
        except InfobloxException:
            raise InfobloxException()
        except requests.HTTPError as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "HTTP error : Error-{}".format(error),
                )
            )
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def get_bearer_token_from_response(
        self,
        json_response,
    ):
        """Retrieve the bearer token from the JSON response.

        Args:
            self: The object instance.
            json_response: The JSON response containing the access token.

        Returns:
            string: The bearer token extracted from the JSON response.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            if "access_token" not in json_response:
                applogger.error(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Access token not found in sentinel api call",
                    )
                )
                raise InfobloxException()
            else:
                bearer_token = json_response.get("access_token")
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Microsoft sentinel access token generated successfully.",
                    )
                )
                return bearer_token
        except KeyError as keyerror:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Key error : Error-{}".format(keyerror),
                )
            )
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def send_indicators_to_threat_intelligence(self, indicator_list):
        """Create indicators in sentinel workspace thereat intelligence section.

        Return response in json formate if status code is in between [200, 299]

        Args:
            url (String): URL of the rest call.
            method (String): HTTP method of rest call. Eg. "GET", etc.
            headers (Dict, optional): headers. Defaults to None.
            params (Dict, optional): parameters. Defaults to None.
            payload (Type : As required by the rest call, optional): body. Defaults to None.

        Returns:
            response : response of the rest call.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            for i in range(consts.MAX_RETRIES):
                upload_indicator_url = consts.UPLOAD_SENTINEL_INDICATORS_URL.format(consts.WORKSPACE_ID)
                applogger.debug(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Calling url: {}".format(upload_indicator_url),
                    )
                )
                body = {
                    "sourcesystem": "Infoblox-TIDE-Threats-Custom",
                    "value": indicator_list,
                }
                try:
                    response = requests.post(
                        url=upload_indicator_url,
                        headers=self.headers,
                        data=json.dumps(body),
                    )
                except requests.ConnectionError as error:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "ConnectionError error : Index = {} : Error-{}".format(i, error),
                        )
                    )
                    time.sleep(random.randint(1, 10))
                    continue

                if response.status_code >= 200 and response.status_code <= 299:
                    applogger.info(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Rest Call Completed, Status code : {}".format(response.status_code),
                        )
                    )
                    response_json = response.json()
                    return response_json
                elif response.status_code == 401:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Unauthorized, Status code : {}, Generating new access token Index = {}".format(
                                response.status_code, i
                            ),
                        )
                    )
                    self.auth_sentinel()
                    continue
                else:
                    applogger.error(
                        self.log_format.format(
                            consts.LOGS_STARTS_WITH,
                            __method_name,
                            self.azure_function_name,
                            "Error while creating indicators, Status code: {}, Error-{}".format(
                                response.status_code, response.content
                            ),
                        )
                    )
                    raise InfobloxException()
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Max retries exceeded.",
                )
            )
            raise InfobloxException()
        except requests.HTTPError as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "HTTP error : Error-{}".format(error),
                )
            )
            raise InfobloxException()
        except requests.RequestException as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Request error : Error-{}".format(error),
                )
            )
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def upload_indicator(
        self,
        indicator_list,
    ):
        """
        Upload indicators to microsoft sentinel.

        Args:
            azure_function_name (str): Name of the azure function
            indicator_list (list): List of indicators to be uploaded

        Raises:
            InfobloxException: If an error occurs while uploading indicators.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Uploading Indicators, Length of records : {}".format(len(indicator_list)),
                )
            )
            response_json = self.send_indicators_to_threat_intelligence(indicator_list)
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Checking for error in response",
                )
            )
            if len(response_json.get("errors")) != 0:
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "Some indicators are failed to create, No. of failed indicators = {}".format(
                            len(response_json.get("errors"))
                        ),
                    )
                )
                self.handle_failed_indicators(indicator_list, response_json)
            else:
                applogger.info(
                    self.log_format.format(
                        consts.LOGS_STARTS_WITH,
                        __method_name,
                        self.azure_function_name,
                        "No error in Response",
                    )
                )
        except InfobloxException:
            raise InfobloxException()
        except Exception as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(error),
                )
            )
            raise InfobloxException()

    def authenticate_infoblox_api(self):
        """Authenticate the Infoblox API."""
        __method_name = inspect.currentframe().f_code.co_name
        try:
            self.headers.update({"Authorization": "Token {}".format(consts.API_TOKEN)})
            applogger.debug(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Headers = {}".format(self.headers),
                )
            )
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def add_xh_to_iso_time_string(self, date_time, x):
        """Add x hours to a given ISO formatted date and time string.

        Args:
            date_time (str): The input date and time string in the format "%Y-%m-%d %H:%M:%S.%f"
            x (int): The number of hours to add to the input date and time.

        Returns:
            str: The new date and time string after adding x hours in the format "%Y-%m-%d %H:%M:%S.%f".

        Raises:
            InfobloxException: When an Infoblox related exception occurs.
            Exception: When any other exception occurs.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Before = {}".format(date_time),
                )
            )
            date_time_obj = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S.%f")
            date_time_obj = date_time_obj + datetime.timedelta(hours=x)
            new_date_time = date_time_obj.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            applogger.info(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "After = {}".format(new_date_time),
                )
            )
            return new_date_time
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()

    def iso_to_epoch_str(self, date_time):
        """Convert an ISO formatted date and time string to epoch time.

        Args:
            date_time (str): The input date and time string in the format "%Y-%m-%d %H:%M:%S.%f"

        Returns:
            str: The epoch time as a string.
        """
        __method_name = inspect.currentframe().f_code.co_name
        try:
            date_time_obj = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S.%f")
            epoch_time = int(date_time_obj.timestamp())
            return str(epoch_time)

        except (TypeError, ValueError) as error:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Type/Value error : Error-{}".format(error),
                )
            )
            raise InfobloxException()
        except Exception as err:
            applogger.error(
                self.log_format.format(
                    consts.LOGS_STARTS_WITH,
                    __method_name,
                    self.azure_function_name,
                    "Unexpected error : Error-{}".format(err),
                )
            )
            raise InfobloxException()
