import os
from unittest import TestCase
from secure_all import AccessManager, AccessManagementException, JSON_FILES_PATH
from pathlib import Path
"""
¿Que tengo que hacer?
Abrir el archivo de test (el que sea para cada tipo)
Obtener la key
Comprobar si es igual
"""
class TestAccessManager(TestCase):
    def setUp(self) -> None:
        my_file = JSON_FILES_PATH + "store_revoke_key.json"
        print(my_file)
        if os.path.exists(my_file):
            os.remove(my_file)


    def test_get_access_key_good(self):
        my_key = AccessManager()
        email = my_key.revoke_key(JSON_FILES_PATH + "test_good.json")
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], email)
