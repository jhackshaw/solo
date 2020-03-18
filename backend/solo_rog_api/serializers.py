from typing import Dict, Any, Optional, cast
from django.contrib.auth import authenticate
from django.contrib.auth.models import AbstractUser
from rest_framework import serializers, exceptions
from rest_framework_simplejwt.tokens import RefreshToken
from .models import (
    AddressType,
    Dic,
    Part,
    ServiceRequest,
    SuppAdd,
    SubInventory,
    Locator,
    Document,
    Status,
    Address,
)


class TokenObtainSerializer(serializers.Serializer):
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, str]:
        user = cast(
            Optional[AbstractUser], authenticate(request=self.context.get("request"))
        )
        if user is None or not user.is_active:
            raise exceptions.AuthenticationFailed()
        refresh = RefreshToken.for_user(user)
        refresh["username"] = user.username
        return {"refresh": str(refresh), "access": str(refresh.access_token)}


class LocatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Locator
        fields = "__all__"


class SubInventorySerializer(serializers.ModelSerializer):
    locators = LocatorSerializer(many=True, read_only=True)

    class Meta:
        model = SubInventory
        fields = "__all__"


class AddressTypeSerializer(serializers.ModelSerializer):
    """ Address Type Serializer """

    class Meta:
        model = AddressType
        fields = "__all__"


class AddressSerializer(serializers.ModelSerializer):
    address_type = AddressTypeSerializer(many=False, read_only=True)

    class Meta:
        model = Address
        fields = "__all__"


class DicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dic
        fields = "__all__"


class PartSerializer(serializers.ModelSerializer):
    class Meta:
        model = Part
        fields = "__all__"


class SuppAddSerializer(serializers.ModelSerializer):
    subinventorys = SubInventorySerializer(many=True, read_only=True)

    class Meta:
        model = SuppAdd
        fields = "__all__"


class StatusSerializer(serializers.ModelSerializer):
    dic = DicSerializer(many=False, read_only=True)

    class Meta:
        model = Status
        fields = "__all__"


class ServiceRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ServiceRequest
        fields = "__all__"


class DocumentSerializer(serializers.ModelSerializer):
    statuses = StatusSerializer(many=True, read_only=True)
    suppadd = SuppAddSerializer(many=False, read_only=True)
    part = PartSerializer(many=False, read_only=True)
    service_request = ServiceRequestSerializer(many=False, read_only=True)
    addresses = AddressSerializer(many=True, read_only=True)

    class Meta:
        model = Document
        fields = "__all__"
