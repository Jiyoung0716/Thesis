from django import forms
from datetime import date

class PersonForm(forms.Form):
    role = forms.ChoiceField(
        choices=(('employee', 'Employee'), ('guest', 'Guest')),
        widget=forms.RadioSelect,
        initial='employee',
        label='Role'
    )
    username = forms.CharField(max_length=80, label='ID')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')
    email = forms.EmailField(required=False, label='Email (optional)')
    full_name = forms.CharField(max_length=120, label='Name')
    dob = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'}),
        input_formats=['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y'],  # ← 이 줄 추가
        label='Date of birth'
    )
    gender = forms.ChoiceField(choices=(('male','Male'),('female','Female'),('other','Other')), required=False)
    country_code = forms.CharField(max_length=8, initial='+353', label='Country code')
    phone = forms.CharField(max_length=50, label='Phone number')
    #agree_sms = forms.BooleanField(required=False, label='Agree to receive SMS')
    address = forms.CharField(max_length=255, required=False, label='Address')

    def clean_dob(self):
        dob = self.cleaned_data.get('dob')
        if dob and dob > date.today():
            raise forms.ValidationError("DOB cannot be in the future")
        return dob
