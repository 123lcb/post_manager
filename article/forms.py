from django import forms
from article.models import Article
from tinymce.widgets import TinyMCE  # 引入富文本编辑器

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Article
        fields = ['title', 'content']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '请输入文章标题'
            }),
            'content': TinyMCE(attrs={  # 使用TinyMCE富文本编辑器
                'class': 'form-control',
                'rows': 15,
                'cols': 80,
                'placeholder': '请输入文章内容'
            })
        }
        labels = {
            'title': '文章标题',
            'content': '文章内容'
        }