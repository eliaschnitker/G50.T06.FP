"""Test para Revoke key"""
from unittest import TestCase
from secure_all import AccessManager, AccessManagementException, JSON_FILES_PATH, AccessKey
from secure_all.storage.keys_json_store import KeysJsonStore
from secure_all.storage.revoke_key_store import RevokeKeyStore


class TestAccessManager(TestCase):
    # pylint: disable=too-many-public-methods, no-member
    """Set Up Class"""
    @classmethod
    def setUpClass(cls) -> None:
        """Creamos desde cero las llaves"""
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
        """Test bueno para revocacion temporal"""
        my_key = AccessManager()
        email = my_key.revoke_key(JSON_FILES_PATH + "test_good_temporal.json")
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], email)

    def test_good_final(self):
        """Test bueno para revocacion final"""
        my_key = AccessManager()
        email = my_key.revoke_key(JSON_FILES_PATH + "test_good_final.json")
        self.assertEqual(["mail1@uc3m.es","mail2@uc3m.es"], email)

    def test_key_izq_deletion(self):
        """Eliminamos llave izquierda"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_deletion(self):
        """Eliminamos llave derecha"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_deletion(self):
        """Eliminamos ambas llaves"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_izq_duplication(self):
        """Duplicamos llave izquierda"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_duplication(self):
        """Duplicamos llave derecha"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_duplication(self):
        """Duplicamos ambas llaves"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_izq_modification(self):
        """Modificamos llave izquierda"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_izq_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_der_modification(self):
        """Modificamos llave derecha"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_der_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_modification(self):
        """Modificamos ambas llaves"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_deletion(self):
        """Eliminamos separador"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_duplication(self):
        """Duplicamos separador"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_separador_modification(self):
        """Editamos separador"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_separador_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_deletion(self):
        """Eliminamos etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_duplication(self):
        """Duplicamos etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta1_modification(self):
        """Modificamos etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta1_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_deletion(self):
        """Eliminamos etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_duplication(self):
        """Duplicamos etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta2_modification(self):
        """Modificamos etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta2_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_deletion(self):
        """Eliminamos etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_deletion.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_duplication(self):
        """Duplicamos etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_duplication.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_etiqueta3_modification(self):
        """Modificamos etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_etiqueta3_modification.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_clave_no_existe(self):
        """Clave no existe"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_clave_no_existe.json")
        self.assertEqual("La clave recibida no existe.", c_m.exception.message)

    def test_clave_mal_formato(self):
        """Clave mal formato"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_clave_mal_formato.json")
        self.assertEqual("key invalid", c_m.exception.message)


    def test_clave_ya_revocada(self):
        """Clave ya revocada"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "revoke_key.json")
        self.assertEqual("La clave fue revocada previamente por este método", c_m.exception.message)

    def test_revocacion_mal(self):
        """Tiempo de revocacion mal"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_revocacion_mal.json")
        self.assertEqual("El tipo de revocacion es invalido", c_m.exception.message)

    def test_razon_mal(self):
        """Razon de revocacion mal"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_razon_mal.json")
        self.assertEqual("Escriba la razon de revocacion", c_m.exception.message)


    def test_archivo_no_existe(self):
        """Archivo no existe"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_archivo_no_existe.json")
        self.assertEqual("Wrong file or file path", c_m.exception.message)

    def test_key_et1_no_comilla(self):
        """Eliminamos comillas etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_duplicate_comilla(self):
        """Duplicamos comillas etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_modification_comilla(self):
        """Modificamos comillas etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_no_comilla(self):
        """Eliminamos comillas etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_duplicate_comilla(self):
        """Duplicamos comillas etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_modification_comilla(self):
        """Modificamos comillas etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_no_comilla(self):
        """Eliminamos comillas etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_duplicate_comilla(self):
        """Duplicamos comillas etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_modification_comilla(self):
        """Modificamos comillas etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_no_comilla(self):
        """Eliminamos comillas de valor 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_duplicate_comilla(self):
        """Duplicamos comillas de valor 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor1_modification_comilla(self):
        """Modificamos comillas de valor 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor1_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_no_comilla(self):
        """Eliminamos comillas de valor 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_duplicate_comilla(self):
        """Duplicamos comillas de valor 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor2_modification_comilla(self):
        """Modificamos comillas de valor 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor2_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_no_comilla(self):
        """Eliminamos comillas de valor 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_no_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_duplicate_comilla(self):
        """Duplicamos comillas de valor 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_duplicate_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_valor3_modification_comilla(self):
        """Modificamos comillas de valor 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_valor3_modification_comilla.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_no_igual(self):
        """Eliminamos igualdad de etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_duplicate_igual(self):
        """Duplicamos igualdad de etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et1_modification_igual(self):
        """Modificamos igualdad de etiqueta 1"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et1_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_no_igual(self):
        """Eliminamos igualdad de etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_duplicate_igual(self):
        """Duplicamos igualdad de etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et2_modification_igual(self):
        """Modificamos igualdad de etiqueta 2"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et2_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_no_igual(self):
        """Eliminamos igualdad de etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_no_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_duplicate_igual(self):
        """Duplicamos igualdad de etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_duplicate_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)

    def test_key_et3_modification_igual(self):
        """Modificamos igualdad de etiqueta 3"""
        my_key = AccessManager()
        with self.assertRaises(AccessManagementException) as c_m:
            my_key.revoke_key(JSON_FILES_PATH + "test_key_et3_modification_igual.json")
        self.assertEqual("JSON Decode Error - Wrong JSON Format", c_m.exception.message)
