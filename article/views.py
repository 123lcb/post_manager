from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from article.models import Article, ShareArticle
from article.forms import ArticleForm


@login_required
def article_list(request):
    """文章列表"""
    articles = Article.objects.filter(
        author=request.user,
        is_deleted=False
    ).order_by('-updated_at')
    return render(request, 'article/list.html', {'articles': articles})


@login_required
def article_create(request):
    """创建文章"""
    if request.method == 'POST':
        form = ArticleForm(request.POST)
        if form.is_valid():
            article = form.save(commit=False)
            article.author = request.user
            article.save()
            messages.success(request, f'文章创建成功！')
            return redirect('article_list')
    else:
        form = ArticleForm()

    return render(request, 'article/form.html', {
        'form': form,
        'title': '创建新文章'
    })


@login_required
def article_edit(request, pk):
    """编辑文章"""
    article = get_object_or_404(Article, pk=pk, author=request.user)

    if request.method == 'POST':
        form = ArticleForm(request.POST, instance=article)
        if form.is_valid():
            updated_article = form.save()
            messages.success(request,
                             f'文章更新成功！最后编辑时间: {updated_article.updated_at.strftime("%Y-%m-%d %H:%M")}')
            return redirect('article_list')
    else:
        form = ArticleForm(instance=article)

    return render(request, 'article/form.html', {
        'form': form,
        'title': '编辑文章',
        'article': article
    })


@login_required
def article_delete(request, pk):
    """删除文章（软删除）"""
    article = get_object_or_404(Article, pk=pk, author=request.user)

    if request.method == 'POST':
        article.is_deleted = True
        article.deleted_at = timezone.now()
        article.save()
        messages.success(request, '文章已移至回收站')
        return redirect('article_list')

    return render(request, 'article/confirm_delete.html', {'article': article})

@login_required
def article_detail(request, pk):
    """文章详情页（用于展示格式化内容）"""
    article = get_object_or_404(Article, pk=pk, author=request.user)
    return render(request, 'article/detail.html', {'article': article})


@login_required
def article_detail(request, pk):
    """文章详情页（支持纯文本回退）"""
    article = get_object_or_404(Article, pk=pk, author=request.user)

    # 检查是否需要显示纯文本版本
    display_plain = request.GET.get('plain') == 'true'

    # 自动检测内容问题并重定向到纯文本视图
    if not display_plain:
        try:
            # 简单的内容验证
            if '<script>' in article.content or '<style>' in article.content:
                display_plain = True
        except:
            display_plain = True

    return render(request, 'article/detail.html', {
        'article': article,
        'display_plain': display_plain
    })
    
@login_required
def share_article(request, pk):
    """共享文章到article_share表"""
    article = get_object_or_404(Article, pk=pk, author=request.user)
    
    # 复制文章到ShareArticle表
    ShareArticle.objects.create(
        title=article.title,
        content=article.content,
        author=article.author,
        created_at=article.created_at,
        updated_at=article.updated_at,
        is_deleted=article.is_deleted,
        deleted_at=article.deleted_at,
        plain_content=article.plain_content
    )
    
    messages.success(request, '文章共享成功！')
    return redirect('article_list')

def share_article_detail(request, pk):
    """共享文章详情页"""
    article = get_object_or_404(ShareArticle, pk=pk)
    return render(request, 'article/share_detail.html', {
        'article': article,
        'display_plain': request.GET.get('plain') == 'true'
    })

def list_share(request):
    """共享文章列表"""
    share_articles = ShareArticle.objects.filter(is_deleted=False).order_by('-created_at')
    return render(request, 'article/list_share.html', {'articles': share_articles})
