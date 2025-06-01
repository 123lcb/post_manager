from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from tinymce.models import HTMLField  # 新增导入


class Article(models.Model):
    title = models.CharField(max_length=200, verbose_name="标题")
    # 将content改为HTMLField以支持富文本
    content = HTMLField(verbose_name="内容")
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="作者")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="更新时间")
    is_deleted = models.BooleanField(default=False, verbose_name="已删除")
    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name="删除时间")
    # 新增纯文本字段用于转换失败时使用
    plain_content = models.TextField(verbose_name="纯文本内容", blank=True, null=True)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        # 自动生成纯文本版本
        if not self.plain_content:
            self.plain_content = self.clean_html_to_text(self.content)
        super().save(*args, **kwargs)

    @staticmethod
    def clean_html_to_text(html):
        """将HTML转换为纯文本"""
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator="\n", strip=True)

    class Meta:
        verbose_name = "文章"
        verbose_name_plural = "文章管理"
        ordering = ['-created_at']