import jwt
import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.exceptions import ParseError, NotFound
from rest_framework.permissions import IsAuthenticated
from .serializers import PrivateUserSerializer, TinyUserSerializer, PublicUserSerializer
from .models import User


class Me(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = PrivateUserSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        serializer = PrivateUserSerializer(
            user,
            data=request.data,
            partial=True,
        )
        if serializer.is_valid():
            user = serializer.save()
            serializer = PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class Users(APIView):

    def post(self, request):
        password = request.data.get("password")
        if not password:
            raise ParseError
        serializer = PrivateUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(password)
            user.save()
            serializer = PrivateUserSerializer(user)
            return Response(serializer.data)
        else:
            return Response(serializer.errors)


class PublicUser(APIView):

    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise NotFound
        serializer = PublicUserSerializer(
            user,
            context={"request": request},
        )
        return Response(serializer.data)


class ChangePassword(APIView):

    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        if not old_password or not new_password:
            raise ParseError
        if user.check_password(old_password):
            user.set_password(new_password)
            user.save()
            return Response(status=status.HTTP_200_OK)
        else:
            raise ParseError


class LogIn(APIView):

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError
        user = authenticate(
            request,
            username=username,
            password=password,
        )
        if user:
            login(request, user)
            return Response(
                {"ok": "welcome!"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error: worng password or username"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class LogOut(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({"ok": "bye!"})


class JWTLogIn(APIView):

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        if not username or not password:
            raise ParseError
        user = authenticate(
            request,
            username=username,
            password=password,
        )
        if user:
            token = jwt.encode(
                {"pk": user.pk},
                settings.SECRET_KEY,
                algorithm="HS256",
            )
            return Response({"token": token})
        else:
            return Response({"error: wrong password or username"})


class GithubLogIn(APIView):
    def post(self, request):
        try:
            code = request.data.get("code")
            if not code:
                return Response(
                    {"error": "GitHub authorization code is missing"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # GitHub OAuth Access Token 요청
            token_response = requests.post(
                f"https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": "Ov23liI4Hk3luFVeheb5",
                    "client_secret": settings.GH_SECRET,
                    "code": code,
                },
            )
            token_data = token_response.json()
            access_token = token_data.get("access_token")

            if not access_token:
                print("❌ GitHub에서 access_token을 받지 못함:", token_data)
                return Response(
                    {"error": "Failed to obtain access token"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # GitHub 사용자 정보 요청
            user_response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            user_data = user_response.json()
            print("👤 GitHub 사용자 데이터:", user_data)

            # GitHub 사용자 이메일 정보 요청
            email_response = requests.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            user_emails = email_response.json()
            print("📩 GitHub 이메일 데이터:", user_emails)

            if not user_emails or not user_emails[0].get("verified"):
                return Response(
                    {"error": "No verified email found"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            verified_email = user_emails[0]["email"]

            try:
                user = User.objects.get(email=verified_email)
                login(request, user)
                print(f"✅ 로그인 성공: {user.email}")
                return Response(status=status.HTTP_200_OK)

            except User.DoesNotExist:
                user = User.objects.create(
                    username=user_data.get("login")
                    or verified_email.split("@")[
                        0
                    ],  # username이 없으면 email 앞부분 사용
                    email=verified_email,
                    name=user_data.get(
                        "name", ""
                    ),  # `name`이 없을 경우 빈 문자열로 처리
                    avatar=user_data.get(
                        "avatar_url", ""
                    ),  # `avatar_url`이 없으면 빈 문자열
                )
                user.set_unusable_password()
                user.save()
                login(request, user)
                print(f"✅ 새 유저 생성 및 로그인: {user.email}")
                return Response(status=status.HTTP_200_OK)

        except Exception as e:
            print("❌ 예외 발생:", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class KakaoLogIn(APIView):

    def post(self, request):
        try:
            code = request.data.get("code")
            access_token = requests.post(
                "https://kauth.kakao.com/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "authorization_code",
                    "client_id": "b2339a1851273cc3558d7b95fbd3a0f4",
                    "redirect_uri": "http://127.0.0.1:3000/social/kakao",
                    "code": code,
                },
            )
            access_token = access_token.json().get("access_token")
            user_data = requests.get(
                "https://kapi.kakao.com/v2/user/me",
                headers={
                    "Authorization": f"Bearer{access_token}",
                    "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
                },
            )
            user_data = user_data.json()
            kakao_account = user_data.get("kakao_account")
            profile = kakao_account.get("profile")
            try:
                user = User.objects.get(email=kakao_account.get("email"))

                login(request, user)
                return Response(status=status.HTTP_200_OK)
            except User.DoesNotExist:
                user = User.objects.create(
                    email=kakao_account.get("email"),
                    username=profile.get("nickname"),
                    name=profile.get("nickname"),
                    avatar=profile.get("profile_image_url"),
                )
                user.set_unusable_password()
                user.save()
                login(request, user)
                return Response(status=status.HTTP_200_OK)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class SignUp(APIView):
    def post(self, request):
        try:
            print(request.data)  # 요청 데이터 확인
            serializer = PrivateUserSerializer(data=request.data)
            password = request.data.get("password")
            if serializer.is_valid():
                user = serializer.save()
                user.set_password(password)
                user.save()
                login(request, user)
                return Response(
                    {"message": "Signup successful"}, status=status.HTTP_201_CREATED
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print("Error:", e)  # 서버에서 오류 로그 출력
            return Response(
                {"error": "Something went wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
