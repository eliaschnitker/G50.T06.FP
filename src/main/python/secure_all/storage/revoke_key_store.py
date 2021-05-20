"""JSON para revoke key"""
from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevokeKeyStore():
    class __RevokeKeyStore(JsonStore):
        """Constantes"""
        # pylint: disable=invalid-name
        INVALID_ITEM = "Invalid item"
        KEY_ALREADY_REVOKE = "La clave fue revocada previamente por este método"

        KEY = "Key"
        ID_FIELD = "_AccessRevokeKey__key"
        REVOCATION = "Revocation"
        REASON = "Reason"

        _FILE_PATH = JSON_FILES_PATH + "store_revoke_key.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Añadir las revoke keys"""
            # pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_revoke_key import AccessRevokeKey

            if not isinstance(item, AccessRevokeKey):
                raise AccessManagementException(self.INVALID_ITEM)

            return super().add_item(item)

        def check_revoke(self, item):
            key = super().find_item(item)
            if key is not None:
                raise AccessManagementException(self.KEY_ALREADY_REVOKE)

    __instance = None

    def __new__(cls):
        if not RevokeKeyStore.__instance:
            RevokeKeyStore.__instance = RevokeKeyStore.__RevokeKeyStore()
        return RevokeKeyStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
