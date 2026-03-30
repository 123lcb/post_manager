from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from tinymce.models import HTMLField
from django.core.exceptions import ValidationError
from mptt.models import MPTTModel, TreeForeignKey


class Category(MPTTModel):
    name = models.CharField(max_length=50, verbose_name="分类名称")
    parent = TreeForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        verbose_name="父级分类"
    )
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name="创建者"
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")

    class MPTTMeta:
        order_insertion_by = ['name']

    class Meta:
        verbose_name = "文章分类"
        verbose_name_plural = "文章分类管理"
        # 添加作者到唯一约束
        unique_together = ('name', 'parent', 'author')

    def __str__(self):
        return self.get_full_path()

    def get_full_path(self):
        """获取完整分类路径"""
        if self.parent:
            return f"{self.parent.get_full_path()}/{self.name}"
        return self.name

    @property
    def level(self):
        """计算当前层级"""
        return self.get_level()

    def save(self, *args, **kwargs):
        """保存前自动设置层级关系"""
        # 确保有作者
        if not hasattr(self, 'author') or not self.author:
            # 尝试从父级继承作者
            if self.parent and self.parent.author:
                self.author = self.parent.author
            else:
                # 对于顶级分类，需要外部设置作者
                raise ValueError("分类必须有关联的作者")

        super().save(*args, **kwargs)

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
    # 新增图片字段
    image = models.ImageField(upload_to='article_images/', null=True, blank=True, verbose_name="文章图片")

    def __str__(self):
        return str(self.title)

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
        """Meta配置类，包含文章模型的元数据
        
        Attributes:
            verbose_name: 单数名称
            verbose_name_plural: 复数名称
            ordering: 默认排序字段
            indexes: 数据库索引配置
        """
        verbose_name = "文章"
        verbose_name_plural = "文章管理"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['is_deleted']),
            models.Index(fields=['deleted_at']),
        ]

    # 回收站相关字段
    is_deleted = models.BooleanField(default=False, verbose_name="已删除")
    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name="删除时间")
    deletion_reason = models.CharField(
        max_length=200,
        null=True,
        blank=True,
        verbose_name="删除原因"
    )

    # 新增分类字段
    category = TreeForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="分类"
    )

    # 在save方法中添加分类验证
    def save(self, *args, **kwargs):
        # 验证分类层级
        if self.category and self.category.level > 3:
            raise ValidationError("分类层级错误")
        super().save(*args, **kwargs)

class ShareArticle(models.Model):
    title = models.CharField(max_length=200, verbose_name="标题")
    content = HTMLField(verbose_name="内容")
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="作者")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="更新时间")
    is_deleted = models.BooleanField(default=False, verbose_name="已删除")
    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name="删除时间")
    plain_content = models.TextField(verbose_name="纯文本内容", blank=True, null=True)
    # 新增审核状态字段
    is_removed = models.BooleanField(default=False, verbose_name="已下架")

    def __str__(self):
        return str(self.title)

    def save(self, *args, **kwargs):
        if not self.plain_content:
            self.plain_content = self.clean_html_to_text(self.content)
        super().save(*args, **kwargs)

    @staticmethod
    def clean_html_to_text(html):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator="\n", strip=True)

    class Meta:
        db_table = "article_share"  # 指定自定义表名
        verbose_name = "分享文章"
        verbose_name_plural = "分享文章管理"
        ordering = ['-created_at']


class Comment(models.Model):
    """文章评论模型"""
    share_article = models.ForeignKey(
        ShareArticle,
        on_delete=models.CASCADE,
        related_name='comments',
        verbose_name="分享文章"
    )
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        verbose_name="评论者"
    )
    content = models.TextField(verbose_name="评论内容")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="评论时间")

    def __str__(self):
        return f"{self.author.username}的评论"

    class Meta:
        verbose_name = "评论"
        verbose_name_plural = "评论管理"
        ordering = ['-created_at']


# class Category(MPTTModel):
#     """多级分类模型"""
#     name = models.CharField(max_length=50, unique=False, verbose_name="分类名称")
#     parent = TreeForeignKey(
#         'self',
#         on_delete=models.CASCADE,
#         null=True,
#         blank=True,
#         related_name='children',
#         verbose_name="父级分类"
#     )
#     author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="创建者")
#     created_at = models.DateTimeField(auto_now_add=True, verbose_name="创建时间")
#
#     class MPTTMeta:
#         order_insertion_by = ['name']
#         level_attr = 'mptt_level'
#         max_level = 3  # 限制最大层级为3级
#
#     class Meta:
#         verbose_name = "文章分类"
#         verbose_name_plural = "文章分类管理"
#         unique_together = ('name', 'parent')  # 同一父分类下名称唯一
#
#     def __str__(self):
#         return self.get_full_path()
#
#     def get_full_path(self):
#         """获取完整分类路径"""
#         ancestors = self.get_ancestors(include_self=True)
#         return '/'.join(category.name for category in ancestors)
#
#     def clean(self):
#         """自定义验证"""
#         # 检查分类层级是否超过限制
#         if self.parent and self.parent.mptt_level >= 2:
#             raise ValidationError("分类层次超过限制，最多支持三级分类")
#
#         # 检查同级分类中是否已存在同名分类
#         siblings = Category.objects.filter(parent=self.parent, name=self.name)
#         if self.pk:  # 更新操作时排除自身
#             siblings = siblings.exclude(pk=self.pk)
#         if siblings.exists():
#             raise ValidationError("该分类已存在")
#
#     def save(self, *args, **kwargs):
#         self.clean()  # 保存前执行验证
#         super().save(*args, **kwargs)