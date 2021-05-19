"""Clase encargada de remover la llave"""
import json
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey
from secure_all.data.attributes.attribute_key import Key
from secure_all.data.attributes.attribute_revocation import Revocation
from secure_all.storage.revoke_key_store import RevokeKeyStore
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.parser.revoke_json_parser import RevokeJsonParser


class AccessRevokeKey():
    """Constantes"""
    REASON_MINUS = "Escriba la razon de revocacion"
    ALMOST_REVOKE = "La clave fue revocada previamente por este método"
    NO_KEY_EXIST = "La clave recibida no existe."


    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.chek_key(key)
        self.__revocation = Revocation(revocation).value
        self.__reason = self.lenght_reason(reason)



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
        """Property that represent the revocation"""
        return self.__revocation

    @revocation.setter
    def revocation(self, value):
        """Setter of the revocation"""
        self.__revocation = value

    @property
    def reason(self):
        """Property that represent the reason"""
        return self.__reason

    @reason.setter
    def reason(self, value):
        """Setter of the reason"""
        self.__reason = value

    @property
    def notification_emails(self):
        """Property  than represent the emails"""
        return self.__notification_emails

    @notification_emails.setter
    def notification_emails(self, value):
        """Setter of the emails"""
        self.__notification_emails = value

    def store_revoke_keys(self):
        """Para tener el almacen de llaves removidas"""
        revoke_store = RevokeKeyStore()
        revoke_store.add_item(self)
        email = KeysJsonStore().find_item(self.__key)
        return email["_AccessKey__notification_emails"]

    @classmethod
    def class_revoke_key(cls, key_file):
        """Clase de remove key"""
        revoke_key_items = RevokeJsonParser(key_file).json_content
        return cls(revoke_key_items[RevokeJsonParser.KEY],
                   revoke_key_items[RevokeJsonParser.REVOCATION],
                   revoke_key_items[RevokeJsonParser.REASON])


    def lenght_reason(self,reason):
        """Comprobamos que existe una razon"""
        if len(reason) == 0:
            raise AccessManagementException(self.REASON_MINUS)
        return reason


    def chek_key(self,key):
        """Comprobamos que la llave existe y no ha sido revocada"""
        store_key = KeysJsonStore()
        find_key = store_key.find_item(key)
        if find_key is None:
            raise AccessManagementException(self.NO_KEY_EXIST)
        revoke_keys_store = RevokeKeyStore()
        revoke_search = revoke_keys_store.find_item(key)
        if revoke_search is not None:
            raise AccessManagementException(self.ALMOST_REVOKE)
