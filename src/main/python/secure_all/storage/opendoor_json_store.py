from secure_all.storage.json_store import JsonStore
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.cfg.access_manager_config import JSON_FILES_PATH

class OpenDoorJsonStore():
    class __OpenDoorJsonStore(JsonStore):
        ID_FIELD = "_AccessKey__key"
        INVALID_ITEM = "Invalid item to be stored as a key"
        KEY_ALREADY_STORED = "key already found in storeRequest"

        _FILE_PATH = JSON_FILES_PATH + "storeOpenDoor.json"
        _ID_FIELD = ID_FIELD

        def add_item(self, item):
            """Implementing the restrictions related to avoid duplicated keys"""
            # pylint: disable=import-outside-toplevel,cyclic-import
            from secure_all.data.access_key import AccessKey

            if not isinstance(item, AccessKey):
                raise AccessManagementException(self.INVALID_ITEM)

            return super().add_item(item)
    __instance = None

    def __new__( cls ):
        if not OpenDoorJsonStore.__instance:
            OpenDoorJsonStore.__instance = OpenDoorJsonStore.__OpenDoorJsonStore()
        return OpenDoorJsonStore.__instance

    def __getattr__ ( self, nombre ):
        return getattr(self.__instance, nombre)

    def __setattr__ ( self, nombre, valor ):
        return setattr(self.__instance, nombre, valor)