"""Module with constants and configurations for the Infoblox integration."""

import os

# *Sentinel related constants
AZURE_CLIENT_ID = os.environ.get("Azure_Client_Id", "")
AZURE_CLIENT_SECRET = os.environ.get("Azure_Client_Secret", "")
AZURE_TENANT_ID = os.environ.get("Azure_Tenant_Id", "")
WORKSPACE_KEY = os.environ.get("Workspace_Key", "")
WORKSPACE_ID = os.environ.get("Workspace_Id", "")

LOG_LEVEL = os.environ.get("LogLevel")

# *Sentinel Apis
AZURE_AUTHENTICATION_URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token"
UPLOAD_SENTINEL_INDICATORS_URL = (
    "https://sentinelus.azure-api.net/{}/threatintelligence:upload-indicators" "?api-version=2022-07-01"
)


# *Infoblox related constants
API_TOKEN = os.environ.get("API_token", "")
BASE_URL = os.environ.get("BaseUrl", "") + "{}"
ENDPOINTS = {
    "active_threats_by_type": "/tide/api/data/threats/state/{}",
}
MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_CHUNK_SIZE = 1024 * 1024

HISTORICAL_TIME_INTERVAL = int(os.environ.get("HISTORICAL_TIME_INTERVAL", "0"))
CURRENT_TIME_INTERVAL = int(os.environ.get("CURRENT_TIME_INTERVAL", "0"))

TYPE = os.environ.get("ThreatType", "")
FIELDS = (
    "id,type,ip,url,tld,email,hash,hash_type,host,domain,profile,property,class,"
    "threat_level,confidence,detected,received,imported,expiration,dga,up,"
    "threat_score,threat_score_rating,confidence_score,confidence_score_rating,"
    "risk_score,risk_score_rating,extended"
)
CONFIDENCE_THRESHOLD = int(os.environ.get("Confidence_Threshold", "0"))
THREAT_LEVEL = int(os.environ.get("Threat_Level", "0"))
FILE_NAME_PREFIX_COMPLETED = "infoblox_completed"
FAILED_INDICATOR_FILE_PREFIX = "infoblox_failed"
FAILED_INDICATORS_TABLE_NAME = "Infoblox_Failed_Indicators"

# *checkpoint related constants
CONN_STRING = os.environ.get("Connection_String", "")
FILE_SHARE_NAME = os.environ.get("File_Share_Name")
FILE_NAME = os.environ.get("Checkpoint_File_Name", "")
FILE_SHARE_NAME_DATA = os.environ.get("File_Share_Name_For_Data", "")
CHUNK_SIZE = 100
MAX_RETRIES = 3

# *Extra constants, use for code readability
LOGS_STARTS_WITH = "Infoblox"
HISTORICAL_I_TO_S_FUNCTION_NAME = "InfobloxHistoricalToAzureStorage"
CURRENT_I_TO_S_FUNCTION_NAME = "InfobloxCurrentToAzureStorage"
INDICATOR_FUNCTION_NAME = "ThreatIndicators"
FAILED_INDICATOR_FUNCTION_NAME = "FailedThreatIndicators"

# *ParseRawIndicatorsData consts
PARSE_RAW_JSON_DATA_FUNCTION_NAME = "InfoBloxParseRawJsonData"
FILE_NAME_PREFIX = "infoblox_raw"
ONE_HOUR_EPOCH_VALUE = 3600

# *Log related constants
LOG_FORMAT = "{}(method = {}) : {} : {}"
