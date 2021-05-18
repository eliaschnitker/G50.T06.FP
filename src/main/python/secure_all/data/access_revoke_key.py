import json

from secure_all import AccessManagementException
from secure_all.data.attributes.attribute_key import Key

class AccessRevokeKey():

    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.__revocation = revocation
        self.__reason = reason

    @property
    def key(self):
        """Property that represent the key"""
        return self.__key

    @key.setter
    def key(self, value):
        """Setter of the key value"""
        self.__key = value

    @property
    def revocation(self):
        """Property that represent the key"""
        return self.__revocation

    @revocation.setter
    def revocation(self, value):
        """Setter of the key value"""
        self.__revocation = value

    @property
    def reason(self):
        """Property that represent the key"""
        return self.__reason

    @reason.setter
    def reason(self, value):
        """Setter of the key value"""
        self.__reason = value

    @staticmethod
    def read_file(file):
        """read the list of stored elements"""
        try:
            with open(file, "r", encoding="utf-8", newline="") as my_file:
                data = json.load(my_file)
        except FileNotFoundError as ex:
            raise AccessManagementException("Wrong file or file path") from ex
        except json.JSONDecodeError as ex:
            raise AccessManagementException("JSON Decode Error - Wrong JSON Format") from ex
        return data

