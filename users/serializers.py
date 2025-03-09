from django.apps import apps
from rest_framework import serializers
from .models import User


class TinyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "name",
            "avatar",
            "username",
        )


class PublicUserSerializer(TinyUserSerializer):
    rooms = serializers.SerializerMethodField()

    def get_rooms(self, obj):
        # 함수 내에서 임포트하여 순환 참조 방지
        from rooms.serializers import RoomListSerializer

        rooms = obj.rooms.all()  # related_name="rooms" 덕분에 접근 가능
        return RoomListSerializer(rooms, many=True, context=self.context).data

    class Meta:
        model = User
        fields = TinyUserSerializer.Meta.fields + ("rooms",)


class PrivateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = (
            "password",
            "is_superuser",
            "id",
            "is_staff",
            "is_active",
            "first_name",
            "last_name",
            "groups",
            "user_permissions",
        )
