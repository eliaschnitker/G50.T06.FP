import os
from unittest import TestCase
from secure_all import AccessManager, AccessManagementException, JSON_FILES_PATH, AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.revoke_key_store import RevokeKeyStore
from pathlib import Path
"""
¿Que tengo que hacer?
Abrir el archivo de test (el que sea para cada tipo)
Obtener la key
Comprobar si es igual
"""
class TestAccessManager(TestCase):

    def setUp(self) -> None:
        revoke_store = RevokeKeyStore()
        revoke_store.empty_store()
        key_store = KeysJsonStore()
        key_store.empty_store()
        my_code = AccessManager()
        new_key = AccessKey.create_key_from_file(JSON_FILES_PATH + "new_key.json")
        new_key.store_keys()
        my_code.revoke_key(JSON_FILES_PATH + "revoke_key.json")
        my_code.get_access_key(JSON_FILES_PATH + "key_ok.json")
        my_code.get_access_key(JSON_FILES_PATH + "key_ok3_resident.json")

    def test_good_temporal(self):
        my_key = AccessManager()
        email = my_key.revoke_key(JSON_FILES_PATH + "test_good_temporal.json")
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], email)

    def test_good_final(self):
        my_key = AccessManager()
        email = my_key.revoke_key(JSON_FILES_PATH + "test_good_final.json")
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], email)

    def test_key_izq_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_izq_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_izq_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_deletion(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_duplication(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_modification(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_clave_no_existe(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_clave_no_existe.json")
        self.assertEqual("La clave recibida no existe.", c_m.exception.message)

    def test_clave_mal_formato(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_clave_mal_formato.json")
        self.assertEqual("key invalid", c_m.exception.message)


    def test_clave_ya_revocada(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "revoke_key.json")
        self.assertEqual("La clave fue revocada previamente por este método", c_m.exception.message)

    def test_revocacion_mal(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_revocacion_mal.json")
        self.assertEqual("El tipo de revocacion es invalido", c_m.exception.message)

    def test_razon_mal(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_razon_mal.json")
        self.assertEqual("Escriba la razon de revocacion", c_m.exception.message)


    def test_archivo_no_existe(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_archivo_no_existe.json")
        self.assertEqual("Wrong file or file path", c_m.exception.message)

    def test_key_et1_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_no_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_duplicate_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_modification_comilla(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_no_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_duplicate_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_modification_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_no_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_duplicate_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_modification_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_no_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_duplicate_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_modification_igual(self):
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)