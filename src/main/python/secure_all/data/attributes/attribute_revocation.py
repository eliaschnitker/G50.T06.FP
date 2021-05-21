"""Attribute class for validating the AccessType"""
from secure_all.data.attributes.attribute import Attribute

class Revocation(Attribute):
    """Clase atributo de revocacion"""
    # pylint: disable=too-few-public-methods
    REVOCATION_TEMPORAL = "Temporal"
    REVOCATION_FINAL = "Final"

    def __init__( self,attr_value ):
        self._validation_pattern =  r'(Temporal|Final)'
        self._error_message = "El tipo de revocacion es invalido"
        self._attr_value = self._validate(attr_value)
