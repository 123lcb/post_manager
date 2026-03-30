# pylint: disable=no-member, E1101
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    GENDER_CHOICES = [
        ('M', '男'),
        ('F', '女'), 
        ('O', '其他')
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    nickname = models.CharField('昵称', max_length=50, blank=True)
    gender = models.CharField('性别', max_length=1, choices=GENDER_CHOICES, blank=True)
    birth_date = models.DateField('出生日期', null=True, blank=True)
    region = models.CharField('地区/国家', max_length=100, blank=True)
    bio = models.TextField('个人简介', max_length=200, blank=True)
    avatar = models.ImageField('头像', upload_to='avatars/', blank=True)
    
    class Meta:
        verbose_name = '用户资料'
        verbose_name_plural = '用户资料'
    
    def __str__(self) -> str:
        return f'{self.user.username}的资料'  # type: ignore[attr-defined]

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
    else:
        UserProfile.objects.create(user=instance)
