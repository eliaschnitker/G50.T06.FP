from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH


class RevokeKeyStore():
    class __RevokeKeyStore(JsonStore):
        # pylint: disable=invalid-name
        ID_FIELD = "_AccessKey__key"
        ACCESS_CODE = "_AccessKey__access_code"
        DNI = "_AccessKey__dni"
        MAIL_LIST = "_AccessKey__notification_emails"
        INVALID_ITEM = "Invalid item"
        KEY_ALREADY_REVOKE = "key already revoke in revokeKeyStore"
        NOT_FOUND_IN_THE_STORE = "Not found in de storeKey"

        _FILE_PATH = JSON_FILES_PATH + "store_revoke_key.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            # pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_revoke_key import AccessRevokeKey

            if not isinstance(item, AccessRevokeKey):
                raise AccessManagementException(self.INVALID_ITEM)

            if not self.find_item(item.key) is None:
                raise AccessManagementException(self.KEY_ALREADY_REVOKE)

            return super().add_item(item)

        def find_item(self, key):
            """find the value key in the _KEY_FIELD"""
            self.load_store()
            for item in self._data_list:
                if item[self._ID_FIELD] == key:
                    return item
            return None

    __instance = None

    def __new__(cls):
        if not RevokeKeyStore.__instance:
            RevokeKeyStore.__instance = RevokeKeyStore.__RevokeKeyStore()
        return RevokeKeyStore.__instance

    def __getattr__(self, nombre):
        return getattr(self.__instance, nombre)

    def __setattr__(self, nombre, valor):
        return setattr(self.__instance, nombre, valor)
