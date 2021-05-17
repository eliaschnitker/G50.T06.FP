"""Module AccessManager with AccessManager Class """

from secure_all.data.access_key import AccessKey
from secure_all.data.access_request import AccessRequest


class AccessManager:
    """AccessManager class, manages the access to a building implementing singleton """
    #pylint: disable=too-many-arguments,no-self-use,invalid-name, too-few-public-methods
    class __AccessManager:
        """Class for providing the methods for managing the access to a building"""

        @staticmethod
        def request_access_code(id_card, name_surname, access_type, email_address, days):
            """ this method give access to the building"""
            my_request = AccessRequest(id_card, name_surname, access_type, email_address, days)
            code = my_request.access_code
            my_request.store_request()
            return my_request.access_code

        @staticmethod
        def get_access_key( keyfile ):
            """Returns the access key for the access code & dni received in a json file"""
            my_key = AccessKey.create_key_from_file(keyfile)
            my_key.store_keys()
            return my_key.key

        @staticmethod
        def open_door(key):
            """Opens the door if the key is valid an it is not expired"""
            """Para la funcionalidad dos debemos registrar en una archivo
            la marca de tiempo de acceso y el valor de la clave"""
            my_key = AccessKey.create_key_from_id(key)
            key_true = my_key.is_valid()
            if key_true is True:
                my_key.store_open_door()
            return AccessKey.create_key_from_id(key).is_valid()


        def RevokeKey(self, file):
            """ Abrimos archivo de RevokeKey
                Buscamos la llave
                Comprobamos si es temporal o final
            """


    __instance = None

    def __new__( cls ):
        if not AccessManager.__instance:
            AccessManager.__instance = AccessManager.__AccessManager()
        return AccessManager.__instance
