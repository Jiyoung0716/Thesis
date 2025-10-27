# experiment/views.py
from django.shortcuts import render
from .models import Person
from .forms import PersonForm

import boto3
from django.conf import settings

def index(request):
    saved = False

    if request.method == 'POST':
        form = PersonForm(request.POST)
        if form.is_valid():
            p = Person(
                role=form.cleaned_data.get('role') or 'employee',
                username=form.cleaned_data['username'],
                email=form.cleaned_data.get('email'),
                full_name=form.cleaned_data['full_name'],
                dob=form.cleaned_data.get('dob'),
                gender=form.cleaned_data.get('gender') or '',
                country_code=form.cleaned_data.get('country_code'),
                phone=form.cleaned_data['phone'],
                address=form.cleaned_data.get('address') or '',
            )
            p.set_password(form.cleaned_data['password'])
            p.save()
            
            # Dynamo DB
            try:
                ddb = boto3.resource('dynamodb', region_name=settings.AWS_REGION)
                table = ddb.Table(settings.DDB_TABLE_SIGNUPS)
                item = {
                    "role": p.role,                     # PK
                    "username": p.username,             # SK
                    "email": p.email or "",
                    "phone": p.phone or "",
                    "address": p.address or "",
                    "created_at": p.created_at.isoformat() if hasattr(p.created_at, "isoformat") else str(p.created_at),
                    "mode_encrypted": bool(getattr(settings, "ENCRYPTION_ENABLED", False)),
                }
                table.put_item(Item=item)
                print("[DDB] put_item OK:", item["role"], item["username"])
            except Exception as e:
                # 실패해도 회원가입 플로우는 계속되게 로그만 남김
                print("[DDB] put_item ERROR:", e)
                
            saved = True
            form = PersonForm()  # 폼 초기화
        else:
            print("❌ Form errors:", form.errors)
    else:
        form = PersonForm()

    return render(request, 'index.html', {'form': form, 'saved': saved})
