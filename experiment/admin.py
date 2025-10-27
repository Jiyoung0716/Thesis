# experiment/admin.py
from django.contrib import admin
from .models import Person

@admin.register(Person)
class PersonAdmin(admin.ModelAdmin):
    list_display = ('id','username', 'password_hash_short', 'role', 'email', 'full_name', 'phone', 'created_at')
    search_fields = ('username', 'full_name', 'email', 'phone')
    list_filter = ('role', 'gender')

    def password_hash_short(self, obj):
        return (obj.password_hash[:12] + '...') if obj.password_hash else ''
    password_hash_short.short_description = 'password_hash'