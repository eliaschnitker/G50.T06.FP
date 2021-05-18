import json

from secure_all import AccessManagementException
from secure_all.data.attributes.attribute_key import Key

class AccessRevokeKey():

    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.__revocation = revocation
        self.__reason = reason
        self.__emails = []
        # justnow = datetime.utcnow()
        # self.__issued_at = datetime.timestamp(justnow)
        # fix self.__issued_at only for testing 13-3-2021 18_49
        self.__issued_at = 1615627129.580297

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

    @property
    def emails(self):
        return self.__emails

    @emails.setter
    def emails(self, value):
        self.__emails = value

