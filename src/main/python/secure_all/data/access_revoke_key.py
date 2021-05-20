"""Clase encargada de remover la llave"""
from secure_all.exception.access_management_exception import AccessManagementException
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
        """Constructor"""
        self.__key = Key(key).value
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

    def returns(self):
        """La funcion devuelve los emails si:
        -existe la clave
        - no ha sido revocada ya"""
        self.chek_key_exist(self.__key)
        revoke_store = RevokeKeyStore()
        revoke_store.check_revoke(self.__key)
        key_store = KeysJsonStore()
        email = key_store.find_item(self.key)
        return email[key_store.MAIL_LIST]



    def store_revoke_keys(self):
        """Para tener el almacen de llaves removidas"""
        revoke_store = RevokeKeyStore()
        revoke_store.add_item(self)
        del revoke_store


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

    def chek_key_exist(self,key):
        """Comprobamos que la llave existe """
        store_key = KeysJsonStore()
        find_key = store_key.find_item(key)
        if find_key is None:
            raise AccessManagementException(self.NO_KEY_EXIST)
