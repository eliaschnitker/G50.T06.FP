"""Parser de revoke key"""

from secure_all.parser.json_parser import JsonParser

class RevokeJsonParser(JsonParser):
    """Parser de revoke key"""
    #pylint: disable=too-few-public-methods
    KEY = "Key"
    REVOCATION = "Revocation"
    REASON = "Reason"
    _key_list = [KEY, REVOCATION, REASON]
