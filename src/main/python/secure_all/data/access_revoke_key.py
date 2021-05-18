import json

from secure_all import AccessManagementException
from secure_all.data.attributes.attribute_key import Key
from secure_all.storage.revoke_key_store import RevokeKeyStore
from secure_all.storage.keys_json_store import KeysJsonStore

class AccessRevokeKey():

    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.__revocation = revocation
        self.__reason = reason
        self.__notification_emails = []
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
        return self.__notification_emails

    @emails.setter
    def emails(self, value):
        self.__notification_emails = value

    def store_revoke_keys(self):
        door_access = RevokeKeyStore()
        door_access.add_item(self)

    def ckeck_if_key_is_revoke(self):
        keys_store = KeysJsonStore()
        key_search = keys_store.find_item(self.__key)
        if key_search is None:
            raise AccessManagementException("La clave recibida no existe.")
        revoke_keys_store = RevokeKeyStore()
        revoke_search = revoke_keys_store.find_item(self.__key)
        if revoke_search is not None:
            raise AccessManagementException("La clave fue revocada previamente por este método")
