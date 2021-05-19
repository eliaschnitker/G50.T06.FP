"""Clase que representa la puerta abierta"""
from datetime import datetime
import json
from secure_all.data.access_key import AccessKey
from secure_all.storage.opendoor_json_store import OpenDoorJsonStore


class AccessOpendoor:
    """La puerta abierta"""
    def __init__(self, key):
        self.__key = key
        just_now = datetime.utcnow()
        self.__issued_at = datetime.timestamp(just_now)

    def __str__(self):
        return "OpenDoor: " + json.dumps(self.__dict__)

    @property
    def key(self):
        """Property that represent the key"""
        return self.__key

    @key.setter
    def key(self, value):
        """Setter of the key value"""
        self.__key = value

    def store_open_door(self):
        """Almacen de puertas abiertas """
        keys_store = OpenDoorJsonStore()
        keys_store.add_item(self)

    @classmethod
    def valid (cls, key):
        """Validar la llave"""
        AccessKey.create_key_from_id(key).is_valid()
        return cls(key)
