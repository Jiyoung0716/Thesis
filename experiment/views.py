# experiment/views.py
from django.shortcuts import render
from .models import Person
from .forms import PersonForm

import boto3
from django.conf import settings

def build_person_from_form(cleaned_data):
    p = Person(
        role=cleaned_data.get('role') or 'employee',
        username=cleaned_data['username'],
        email=cleaned_data.get('email'),
        full_name=cleaned_data['full_name'],
        dob=cleaned_data.get('dob'),
        gender=cleaned_data.get('gender') or '',
        country_code=cleaned_data.get('country_code'),
        phone=cleaned_data['phone'],
        address=cleaned_data.get('address') or '',
    )
    p.set_password(cleaned_data['password'])
    return p


def save_person_to_dynamodb(person):
    try:
        ddb = boto3.resource('dynamodb', region_name=settings.AWS_REGION)
        table = ddb.Table(settings.DDB_TABLE_SIGNUPS)
        created_at = getattr(person, "created_at", None)

        item = {
            "role": person.role,                     # PK
            "username": person.username,             # SK
            "email": person.email or "",
            "phone": person.phone or "",
            "address": person.address or "",
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            "mode_encrypted": bool(getattr(settings, "ENCRYPTION_ENABLED", False)),
        }
        table.put_item(Item=item)
        print("[DDB] put_item OK:", item["role"], item["username"])

    except Exception as e:
        print("[DDB] put_item ERROR:", e)

def index(request):
    saved = False
    # POST면 데이터 바인딩, 아니면 빈 폼
    form = PersonForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():
        person = build_person_from_form(form.cleaned_data)
        person.save()
        save_person_to_dynamodb(person)

        saved = True
        form = PersonForm()  # 폼 초기화해서 빈 폼 다시 보여줌
    elif request.method == 'POST':
        # 유효성 실패 시
        print("❌ Form errors:", form.errors)

    return render(request, 'index.html', {'form': form, 'saved': saved})
    
    