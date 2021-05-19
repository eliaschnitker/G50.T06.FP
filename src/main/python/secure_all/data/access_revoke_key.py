import json

from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.access_key import AccessKey
from secure_all.data.attributes.attribute_key import Key
from secure_all.data.attributes.attribute_revocation import Revocation
from secure_all.storage.revoke_key_store import RevokeKeyStore
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.parser.revoke_json_parser import RevokeJsonParser


class AccessRevokeKey():

    REASON_MINUS = "Escriba la razon de revocacion"
    ALMOST_REVOKE = "La clave fue revocada previamente por este método"
    NO_KEY_EXIST = "La clave recibida no existe."


    def __init__(self, key, revocation, reason):
        self.__key = Key(key).value
        self.chek_key(key)
        self.__revocation = Revocation(revocation).value
        self.__reason = self.lenght_reason(reason)
        self.__notification_emails = []


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
    def notification_emails(self):
        return self.__notification_emails

    @notification_emails.setter
    def notification_emails(self, value):
        self.__notification_emails = value

    def store_revoke_keys(self):
        revoke_store = RevokeKeyStore()
        revoke_store.add_item(self)
        return revoke_store

    @classmethod
    def class_revoke_key(cls, key_file):
        """Class method from creating an instance of AccessKey
        from the content of a file according to RF2"""
        revoke_key_items = RevokeJsonParser(key_file).json_content
        return cls(revoke_key_items[RevokeJsonParser.KEY],
                   revoke_key_items[RevokeJsonParser.REVOCATION],
                   revoke_key_items[RevokeJsonParser.REASON])

    def clave_valida(self,key):
        """Comprobamos que la clave es valida"""
        valid = AccessKey.is_valid(key)
        if valid is True:
            return True

    def lenght_reason(self,reason):
        """Comprobamos que existe una razon"""
        if len(reason)==0:
            raise AccessManagementException(self.REASON_MINUS)
        return reason


    def chek_key(self,key):
        """Comprobamos que la llave existe y no ha sido revocada"""
        keys_store = KeysJsonStore()
        key_search = keys_store.find_item(key)
        if key_search is None:
            raise AccessManagementException(self.NO_KEY_EXIST)
        revoke_keys_store = RevokeKeyStore()
        revoke_search = revoke_keys_store.find_item(key)
        if revoke_search is not None:
            raise AccessManagementException(self.ALMOST_REVOKE)



    def cargar_emails(self,key):
        """Cargamos los emails"""
        keys_store = KeysJsonStore()
        key_search = keys_store.find_item(key)
        for i in key_search:
            self.__notification_emails.append(i["_AccessKey__notification_emails"])
