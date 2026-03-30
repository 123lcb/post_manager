from article.models import Article, Category
from tinymce.widgets import TinyMCE  # 引入富文本编辑器
from django import forms
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Article
        fields = ['title', 'content', 'category', 'image']  # 添加 image 字段
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '请输入文章标题'
            }),
            'content': TinyMCE(attrs={
                'class': 'form-control',
                'rows': 15,
                'cols': 80,
                'placeholder': '请输入文章内容'
            }),
            'category': forms.Select(attrs={
                'class': 'form-control',
                'id': 'article-category'
            }),
            'image': forms.ClearableFileInput(attrs={'class': 'form-control'})  # 添加图片输入框
        }
        labels = {
            'title': _('文章标题'),
            'content': _('文章内容'),
            'category': _('文章分类'),
            'image': _('文章图片')
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        if user:
            self.fields['category'].queryset = Category.objects.filter(
                author=user,
                children__isnull=True
            )

class RestoreForm(forms.Form):
    """恢复文章表单"""
    confirm = forms.BooleanField(
        required=True,
        label=_('我明白此操作不可撤销'),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class CommentForm(forms.ModelForm):
    """评论表单"""
    class Meta:
        from article.models import Comment
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请输入评论内容'
            })
        }
        labels = {
            'content': '评论内容'
        }

class EmptyTrashForm(forms.Form):
    """清空回收站表单"""
    days = forms.IntegerField(
        required=False,
        min_value=0,
        max_value=365,
        label=_('删除早于多少天的文章'),
        help_text=_('输入0表示删除回收站中所有文章'),
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '0'})
    )
    confirm = forms.BooleanField(
        required=True,
        label=_('我明白此操作不可撤销'),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'parent']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '请输入分类名称'
            }),
            'parent': forms.Select(attrs={
                'class': 'form-control',
                'id': 'category-parent'
            }),
        }

    def __init__(self, *args, **kwargs):
        # 从参数中提取user
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # 只显示当前用户的分类
        if self.user:
            self.fields['parent'].queryset = Category.objects.filter(author=self.user)

    def clean(self):
        """自定义表单验证"""
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        parent = cleaned_data.get('parent')

        # 确保有用户上下文
        if not self.user:
            raise ValidationError("用户未登录")

        # 检查层级深度
        if parent and parent.level >= 2:
            raise ValidationError("分类层次超过限制，最多支持三级分类")

        # 检查同名分类
        if name:
            siblings = Category.objects.filter(
                parent=parent,
                name=name,
                author=self.user
            )
            if self.instance and self.instance.pk:
                siblings = siblings.exclude(pk=self.instance.pk)
            if siblings.exists():
                raise ValidationError("该分类已存在")

        return cleaned_data