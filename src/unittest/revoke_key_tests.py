from unittest import TestCase
from secure_all import AccessManager, AccessManagementException
from pathlib import Path
"""
¿Que tengo que hacer?
Abrir el archivo de test (el que sea para cada tipo)
Obtener la key
Comprobar si es igual
"""
class TestAccessManager(TestCase):
    def test_get_access_key_good(self):
        dir_hom = str(Path.home())
        dir_proyecto = "/PycharmProjects/G50.T06.EG3/src/JSONFILES/"
        fichero = "test_good.json"
        my_file = dir_hom + dir_proyecto + fichero
        my_key=AccessManager()
        key=my_key.get_access_key(my_file)
        self.assertEqual("b07380a18b5e64c73539accecf90c111bf12d04a9e2effad1a6d32812c915dd4", key)

    def test_get_access_key_etiqueta_Access(self):
        dir_hom = str(Path.home())
        dir_proyecto = "/PycharmProjects/G50.T06.EG3/src/JSONFILES/"
        fichero = "test_bad_etiquetaAccess.json"
        my_file = dir_hom + dir_proyecto + fichero
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as cm:
            key = my_key.get_access_key(my_file)
        self.assertEqual("Etiqueta de AccessCode incorrecta", cm.exception.message)