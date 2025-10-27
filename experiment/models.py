from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

# ⬇️ 추가: 토글/키 읽어서 Fernet 사용
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


def _fernet():
    if settings.ENCRYPTION_ENABLED and settings.FERNET_KEY:
        return Fernet(settings.FERNET_KEY.encode())
    return None

def _is_encrypted(val: str) -> bool:
    return isinstance(val, str) and val.startswith("gAAAA")  # Fernet 토큰의 전형적 prefix

def _enc(val: str) -> str:
    """토글이 켜져있고 아직 암호화되지 않은 값만 암호화"""
    if not val:
        return val
    f = _fernet()
    if not f or _is_encrypted(val):
        return val
    return f.encrypt(val.encode()).decode()


class Person(models.Model):
    ROLE_CHOICES = (('employee','Employee'), ('guest','Guest'))
    GENDER_CHOICES = (('male','Male'), ('female','Female'), ('other','Other'))

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    username = models.CharField(max_length=80, unique=True)
    password_hash = models.CharField(max_length=128)   # store hashed password

    # ⚠️ EmailField라 해도 DB 제약은 없음 → 암호문 저장 가능(형식검사는 폼에서만)
    email = models.EmailField(blank=True, null=True)

    full_name = models.CharField(max_length=120)
    dob = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True)
    country_code = models.CharField(max_length=8, default='+353')

    phone = models.CharField(max_length=50)
    agree_sms = models.BooleanField(default=False)
    address = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(default=timezone.now)

    # ✅ 저장 시 항상 PII 필드 암호화 보증(토글 True일 때만)
    def save(self, *args, **kwargs):
        # 비밀번호는 해시로 유지 (변경 없음)
        # 암호화 대상: email, full_name, phone, address  (dob은 date 타입이므로 여기선 제외)
        if self.email and not _is_encrypted(self.email):
            self.email = _enc(self.email)
        if self.full_name and not _is_encrypted(self.full_name):
            self.full_name = _enc(self.full_name)
        if self.phone and not _is_encrypted(self.phone):
            self.phone = _enc(self.phone)
        if self.address and not _is_encrypted(self.address):
            self.address = _enc(self.address)
        super().save(*args, **kwargs)

    def set_password(self, raw_password):
        self.password_hash = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password_hash)

    # 🔒 암호문일 때도 깨지지 않도록 마스킹 수정
    def masked_phone(self):
        p = (self.phone or "")
        if _is_encrypted(p):
            return "•••• (encrypted)"
        if len(p) <= 4:
            return "****"
        return p[:-4] + "****"

    def masked_email(self):
        e = self.email or ""
        if _is_encrypted(e):
            return "***@*** (encrypted)"
        local, _, domain = e.partition('@')
        if not domain:
            return "***"
        if len(local) <= 2:
            local_masked = (local[:1] + '***') if local else '***'
        else:
            local_masked = local[:2] + '***'
        return f"{local_masked}@{domain}"

    def __str__(self):
        # full_name이 암호문일 수 있으니 username만 표시
        return f"{self.username}"
