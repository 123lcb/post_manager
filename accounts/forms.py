from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import random,os
from PIL import Image
from io import BytesIO

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, label='邮箱')
    verification_code = forms.CharField(
        required=True,
        label='验证码',
        widget=forms.TextInput(attrs={'placeholder': '请输入邮箱验证码'})
    )
    
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "verification_code")

    def clean_verification_code(self):
        code = self.cleaned_data.get('verification_code')
        session_code = self.data.get('email_verification_code')
        if not session_code:
            session_code = self.initial.get('request').session.get('email_verification_code', '')
        if code != session_code:
            raise ValidationError('验证码错误')
        return code

    def save(self, commit=True):
        user = super(RegisterForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label='用户名',
        widget=forms.TextInput(attrs={'autocomplete': 'username'})
    )
    password = forms.CharField(
        label='密码', 
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'})
    )
    
    error_messages = {
        'invalid_login': "用户名或密码错误",
        'inactive': "该账号已被禁用",
    }

def generate_verification_code():
    return str(random.randint(100000, 999999))

class UserProfileForm(forms.ModelForm):
    GENDER_CHOICES = [
        ('', '未选择'),
        ('M', '男'),
        ('F', '女'),
        ('O', '其他')
    ]
    
    nickname = forms.CharField(
        label='昵称',
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    
    gender = forms.ChoiceField(
        label='性别',
        choices=GENDER_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    birth_date = forms.DateField(
        label='出生日期',
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    
    region = forms.CharField(
        label='地区/国家',
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    
    bio = forms.CharField(
        label='个人简介',
        required=False,
        max_length=200,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3})
    )
    
    avatar = forms.ImageField(
        label='头像',
        required=False,
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        from .models import UserProfile
        model = UserProfile
        fields = ['nickname', 'gender', 'birth_date', 'region', 'bio', 'avatar']
        
    def clean_avatar(self):
        avatar = self.cleaned_data.get('avatar')
        if avatar:
            # 验证文件大小 (5MB)
            if avatar.size > 5 * 1024 * 1024:
                raise ValidationError("头像文件大小不能超过5MB")
            
            # 验证文件类型
            valid_extensions = ['.jpg', '.jpeg', '.png']
            ext = os.path.splitext(avatar.name)[1].lower()
            if ext not in valid_extensions:
                raise ValidationError("不支持的图片格式，请使用JPG或PNG格式")
        return avatar