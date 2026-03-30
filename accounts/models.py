# pylint: disable=no-member, E1101
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

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
    is_frozen = models.BooleanField('是否冻结', default=False)
    
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

class UserActionLog(models.Model):
    """管理员操作记录"""
    ACTION_CHOICES = [
        ('FREEZE', '冻结账号'),
        ('UNFREEZE', '解冻账号'),
    ]
    
    admin = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='admin_actions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_actions')
    action = models.CharField('操作类型', max_length=10, choices=ACTION_CHOICES)
    reason = models.TextField('操作原因', blank=True)
    created_at = models.DateTimeField('操作时间', default=timezone.now)
    
    class Meta:
        verbose_name = '管理员操作记录'
        verbose_name_plural = '管理员操作记录'
        ordering = ['-created_at']
    
    def __str__(self) -> str:
        return f'{self.admin} {self.get_action_display()} {self.user}'

class Favorite(models.Model):
    """用户收藏文章"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='favorites')
    article = models.ForeignKey('article.ShareArticle', on_delete=models.CASCADE)
    created_at = models.DateTimeField('收藏时间', auto_now_add=True)

    class Meta:
        verbose_name = '收藏'
        verbose_name_plural = '收藏'
        unique_together = ('user', 'article')  # 防止重复收藏
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'{self.user.username}收藏{self.article.title}'
