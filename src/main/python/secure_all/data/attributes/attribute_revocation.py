"""Attribute class for validating the AccessType"""
from secure_all.exception.access_management_exception import AccessManagementException
from secure_all.data.attributes.attribute import Attribute

class Revocation(Attribute):
    REVOCATION_TEMPORAL = "Temporal"
    REVOCATION_FINAL = "Final"

    def __init__( self,attr_value ):
        self._validation_pattern =  r'(Temporal|Final)'
        self._error_message = "El tipo de revocacion es invalido"
        self._attr_value = self._validate(attr_value)