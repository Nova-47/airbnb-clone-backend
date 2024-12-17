from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError


class User(AbstractUser):

    class GenderChoices(models.TextChoices):
        MALE = ("male", "Male")
        FEMALE = ("female", "Female")
        ANONYMOUS = ("anonymous", "Anonymous")

    class LanguageChoices(models.TextChoices):
        KR = ("kr", "Korean")
        EN = ("en", "English")

    class CurrencyChoices(models.TextChoices):
        WON = "won", "Korean Won"
        USD = "usd", "Dollar"

    first_name = models.CharField(
        max_length=150,
        editable=False,
    )
    last_name = models.CharField(
        max_length=150,
        editable=False,
    )
    avatar = models.ImageField(blank=True)
    name = models.CharField(max_length=150, default="")
    is_host = models.BooleanField(default=False)
    gender = models.CharField(
        max_length=10,
        choices=GenderChoices.choices,
    )
    language = models.CharField(
        max_length=2,
        choices=LanguageChoices.choices,
    )
    currency = models.CharField(
        max_length=5,
        choices=CurrencyChoices.choices,
    )

    def clean(self):
        super().clean()
        # 관리자만 ANONYMOUS를 선택할 수 있도록 검증
        if self.gender == self.GenderChoices.ANONYMOUS and not self.is_staff:
            raise ValidationError("Only administrators can select 'Anonymous'.")
