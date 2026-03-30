from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from article.models import Article, ShareArticle
from article.forms import ArticleForm, RestoreForm, EmptyTrashForm, CategoryForm
from django.db.models import Q
from django.core.paginator import Paginator
from django.utils.translation import gettext_lazy as _
from article.models import Category
from django.http import JsonResponse
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_exempt
from .deepseek_api import generate_summary, generate_statistical_summary
import logging


@login_required
def article_list(request):
    """文章列表 - 添加分类创建提示"""
    # 获取当前用户的所有文章
    articles = Article.objects.filter(
        author=request.user,
        is_deleted=False
    ).order_by('-updated_at')

    # 获取当前用户的所有最末级分类（用于筛选）
    categories = Category.objects.filter(
        author=request.user,
        children__isnull=True
    )

    # 分类筛选
    category_id = request.GET.get('category')
    if category_id:
        articles = articles.filter(category_id=category_id)
        selected_category = get_object_or_404(Category, id=category_id, author=request.user)
    else:
        selected_category = None

    # 搜索功能
    search_query = request.GET.get('q')
    if search_query:
        articles = articles.filter(
            Q(title__icontains=search_query) |
            Q(content__icontains=search_query)
        )

    # 检查是否有新创建的分类
    category_created = None
    if 'category_created' in request.session:
        try:
            category_id = request.session.pop('category_created')
            category_created = Category.objects.get(id=category_id, author=request.user)
        except Category.DoesNotExist:
            pass

    # 分页处理
    paginator = Paginator(articles, 10)  # 每页10条
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'article/list.html', {
        'articles': page_obj,
        'categories': categories,
        'selected_category': selected_category,
        'search_query': search_query or '',
        'category_created': category_created,
        'is_paginated': paginator.num_pages > 1
    })


@login_required
def article_create(request):
    categories = Category.objects.filter(
        author=request.user,
        children__isnull=True
    )
    all_categories = Category.objects.filter(author=request.user)

    if request.method == 'POST':
        form = ArticleForm(request.POST, request.FILES, user=request.user)  # 添加 request.FILES
        if form.is_valid():
            article = form.save(commit=False)
            article.author = request.user
            article.save()
            messages.success(request, f'文章创建成功！')
            return redirect('article_list')
    else:
        form = ArticleForm(user=request.user)

    return render(request, 'article/form.html', {
        'form': form,
        'title': '创建新文章',
        'categories': categories,
        'all_categories': all_categories
    })

@login_required
def article_edit(request, pk):
    article = get_object_or_404(Article, pk=pk, author=request.user)
    categories = Category.objects.filter(
        author=request.user,
        children__isnull=True
    )
    all_categories = Category.objects.filter(author=request.user)

    if request.method == 'POST':
        form = ArticleForm(request.POST, request.FILES, instance=article, user=request.user)  # 添加 request.FILES
        if form.is_valid():
            updated_article = form.save()
            messages.success(request,
                             f'文章更新成功！最后编辑时间: {updated_article.updated_at.strftime("%Y-%m-%d %H:%M")}')
            return redirect('article_list')
    else:
        form = ArticleForm(instance=article, user=request.user)

    return render(request, 'article/form.html', {
        'form': form,
        'title': '编辑文章',
        'article': article,
        'categories': categories,
        'all_categories': all_categories
    })


@login_required
def article_delete(request, pk):
    """删除文章（软删除）"""
    article = get_object_or_404(Article, pk=pk, author=request.user)

    if request.method == 'POST':
        article.is_deleted = True
        article.deleted_at = timezone.now()
        article.deletion_reason = request.POST.get('deletion_reason', '')
        article.save()

        messages.success(request, '文章已移至回收站')
        return redirect('article_list')

    return render(request, 'article/confirm_delete.html', {'article': article})


@login_required
def article_detail(request, pk):
    """文章详情页（支持纯文本回退）"""
    article = get_object_or_404(Article, pk=pk, author=request.user)
    # summary = generate_summary(article.content)
    # statistical_summary = generate_statistical_summary(article.content)
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
        # 'summary': summary,
        # 'statistical_summary': statistical_summary
    })


@login_required
def trash_list(request):
    """回收站列表"""
    # 获取当前用户的已删除文章
    deleted_articles = Article.objects.filter(
        author=request.user,
        is_deleted=True
    ).order_by('-deleted_at')

    # 搜索功能
    search_query = request.GET.get('q')
    if search_query:
        # 修正这里：添加逗号并正确关闭filter方法
        deleted_articles = deleted_articles.filter(
            Q(title__icontains=search_query) |
            Q(content__icontains=search_query)
        )

    # 分页处理
    paginator = Paginator(deleted_articles, 10)  # 每页10条
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'article/trash_list.html', {
        'page_obj': page_obj,
        'search_query': search_query or ''
    })


@login_required
def restore_article(request, pk):
    """恢复文章"""
    article = get_object_or_404(Article, pk=pk, author=request.user, is_deleted=True)

    if request.method == 'POST':
        form = RestoreForm(request.POST)
        if form.is_valid():
            article.is_deleted = False
            article.deleted_at = None
            article.deletion_reason = None
            article.save()

            messages.success(request, f'文章 "{article.title}" 已成功恢复！')
            return redirect('trash_list')
    else:
        form = RestoreForm()

    return render(request, 'article/restore_confirm.html', {
        'article': article,
        'form': form
    })


@login_required
def permanent_delete(request, pk):
    """永久删除文章"""
    article = get_object_or_404(Article, pk=pk, author=request.user, is_deleted=True)

    if request.method == 'POST':
        article_title = article.title
        article.delete()  # 物理删除
        messages.warning(request, f'文章 "{article_title}" 已永久删除！')
        return redirect('trash_list')

    return render(request, 'article/permanent_delete_confirm.html', {
        'article': article
    })


@login_required
def empty_trash(request):
    """清空回收站"""
    if request.method == 'POST':
        form = EmptyTrashForm(request.POST)
        if form.is_valid():
            # 获取所有符合条件的文章
            articles = Article.objects.filter(
                author=request.user,
                is_deleted=True
            )

            # 检查删除时间范围
            days = form.cleaned_data.get('days', 0)
            if days > 0:
                cutoff_date = timezone.now() - timezone.timedelta(days=days)
                articles = articles.filter(deleted_at__lte=cutoff_date)

            count = articles.count()

            # 执行删除
            articles.delete()

            messages.warning(request, f'已永久删除 {count} 篇文章！')
            return redirect('trash_list')
    else:
        form = EmptyTrashForm()

    return render(request, 'article/empty_trash.html', {
        'form': form
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
    comments = article.comments.all().order_by('-created_at')
    
    if request.method == 'POST' and request.user.is_authenticated:
        from article.forms import CommentForm
        form = CommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.share_article = article
            comment.author = request.user
            comment.save()
            return redirect('share_article_detail', pk=pk)
    else:
        from article.forms import CommentForm
        form = CommentForm()

    return render(request, 'article/share_detail.html', {
        'article': article,
        'display_plain': request.GET.get('plain') == 'true',
        'comments': comments,
        'comment_form': form
    })


def list_share(request):
    """共享文章列表"""
    share_articles = ShareArticle.objects.filter(is_deleted=False).order_by('-created_at')
    return render(request, 'article/list_share.html', {'articles': share_articles})


# @login_required
# def category_list(request):
#     """分类列表"""
#     # 获取当前用户的所有分类
#     categories = Category.objects.filter(author=request.user)
#
#     # 按树形结构组织
#     root_categories = categories.filter(parent__isnull=True)
#
#     return render(request, 'article/category_list.html', {
#         'root_categories': root_categories
#     })
#
#
# @login_required
# def category_create(request):
#     """创建分类"""
#     if request.method == 'POST':
#         form = CategoryForm(request.POST, user=request.user)
#         if form.is_valid():
#             try:
#                 category = form.save(commit=False)
#                 category.author = request.user
#                 category.save()
#                 messages.success(request, _('分类创建成功: %(path)s') % {'path': category.get_full_path()})
#                 return redirect('category_list')
#             except ValidationError as e:
#                 messages.error(request, e.message)
#     else:
#         form = CategoryForm(user=request.user)
#
#     return render(request, 'article/category_form.html', {
#         'form': form,
#         'title': _('创建新分类')
#     })


@login_required
def category_edit(request, pk):
    """编辑分类"""
    category = get_object_or_404(Category, pk=pk, author=request.user)

    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category, user=request.user)
        if form.is_valid():
            try:
                updated_category = form.save()
                messages.success(request, _('分类更新成功: %(path)s') % {'path': updated_category.get_full_path()})
                return redirect('category_list')
            except ValidationError as e:
                messages.error(request, e.message)
    else:
        form = CategoryForm(instance=category, user=request.user)

    return render(request, 'article/category_form.html', {
        'form': form,
        'title': _('编辑分类'),
        'category': category
    })


@login_required
def category_delete(request, pk):
    """删除分类"""
    category = get_object_or_404(Category, pk=pk, author=request.user)

    # 检查是否有文章或子分类
    has_articles = Article.objects.filter(category=category).exists()
    has_children = category.children.exists()

    if request.method == 'POST':
        # 处理删除操作
        if not has_articles and not has_children:
            category.delete()
            messages.success(request, _('分类 "%(name)s" 已删除') % {'name': category.name})
            return redirect('category_list')
        else:
            messages.error(request, _('无法删除分类 "%(name)s"，因为它包含子分类或文章') % {'name': category.name})

    return render(request, 'article/category_confirm_delete.html', {
        'category': category,
        'has_articles': has_articles,
        'has_children': has_children
    })


# @login_required
# def ajax_create_category(request):
#     """AJAX创建分类"""
#     if request.method == 'POST':
#         name = request.POST.get('name')
#         parent_id = request.POST.get('parent')
#
#         # 验证分类名称
#         if not name:
#             return JsonResponse({'success': False, 'error': '分类名称不能为空'})
#
#         # 创建分类
#         try:
#             category = Category(
#                 name=name,
#                 author=request.user
#             )
#
#             # 设置父分类
#             if parent_id:
#                 parent = Category.objects.get(id=parent_id, author=request.user)
#
#                 # 检查层级深度
#                 if parent.level >= 2:
#                     return JsonResponse({'success': False, 'error': '分类层次超过限制，最多支持三级分类'})
#
#                 category.parent = parent
#
#             # 检查同级分类中是否已存在同名分类
#             siblings = Category.objects.filter(
#                 parent=category.parent,
#                 name=name,
#                 author=request.user
#             )
#             if siblings.exists():
#                 return JsonResponse({'success': False, 'error': '该分类已存在'})
#
#             category.save()
#             return JsonResponse({
#                 'success': True,
#                 'category_id': category.id,
#                 'full_path': category.get_full_path()
#             })
#         except Exception as e:
#             return JsonResponse({'success': False, 'error': str(e)})
#
#     return JsonResponse({'success': False, 'error': '无效请求'})


@login_required
def category_list(request):
    """分类列表 - 修复版"""
    # 获取当前用户的所有分类
    categories = Category.objects.filter(author=request.user)

    # 按树形结构组织
    root_categories = categories.filter(parent__isnull=True)

    return render(request, 'article/category_list.html', {
        'root_categories': root_categories
    })


# @login_required
# def category_create(request):
#     """创建分类 - 独立页面版"""
#     if request.method == 'POST':
#         form = CategoryForm(request.POST, user=request.user)
#         if form.is_valid():
#             try:
#                 category = form.save(commit=False)
#                 category.author = request.user
#                 category.save()
#                 messages.success(request, f'分类创建成功: {category.get_full_path()}')
#                 return redirect('category_list')
#             except ValidationError as e:
#                 for error in e.messages:
#                     messages.error(request, error)
#     else:
#         form = CategoryForm(user=request.user)
#
#     return render(request, 'article/category_form.html', {
#         'form': form,
#         'title': '创建新分类'
#     })
@login_required
def category_create(request):
    """创建分类 - 添加成功提示"""
    if request.method == 'POST':
        form = CategoryForm(request.POST, user=request.user)
        if form.is_valid():
            try:
                category = form.save(commit=False)
                category.author = request.user
                category.save()

                # 将新创建的分类ID存入session
                request.session['category_created'] = category.id

                # 重定向回文章列表并显示提示
                return redirect('article_list')
            except ValidationError as e:
                for error in e.messages:
                    messages.error(request, error)
    else:
        form = CategoryForm(user=request.user)

    return render(request, 'article/category_form.html', {
        'form': form,
        'title': '创建新分类'
    })

@login_required
@csrf_exempt  # 临时禁用CSRF验证用于调试
def ajax_create_category(request):
    """AJAX创建分类 - 修复版"""
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        parent_id = request.POST.get('parent', '')

        # 验证分类名称
        if not name:
            return JsonResponse({
                'success': False,
                'error': '分类名称不能为空'
            })

        # 创建分类
        try:
            category = Category(
                name=name,
                author=request.user
            )

            # 设置父分类
            if parent_id:
                try:
                    parent = Category.objects.get(id=parent_id, author=request.user)

                    # 检查层级深度
                    if parent.level >= 2:
                        return JsonResponse({
                            'success': False,
                            'error': '分类层次超过限制，最多支持三级分类'
                        })

                    category.parent = parent
                except Category.DoesNotExist:
                    return JsonResponse({
                        'success': False,
                        'error': '父分类不存在'
                    })

            # 检查同级分类中是否已存在同名分类
            siblings = Category.objects.filter(
                parent=category.parent,
                name=name,
                author=request.user
            )
            if siblings.exists():
                return JsonResponse({
                    'success': False,
                    'error': '该分类已存在'
                })

            category.save()
            return JsonResponse({
                'success': True,
                'category_id': category.id,
                'full_path': category.get_full_path()
            })
        except ValidationError as e:
            # 捕获模型验证错误
            errors = '; '.join(e.messages)
            return JsonResponse({
                'success': False,
                'error': f'验证错误: {errors}'
            })
        except Exception as e:
            # 捕获其他异常
            return JsonResponse({
                'success': False,
                'error': f'服务器错误: {str(e)}'
            })

    return JsonResponse({
        'success': False,
        'error': '无效请求方法'
    })


logger = logging.getLogger(__name__)


@login_required
def article_summary(request, pk):
    article = get_object_or_404(Article, pk=pk, author=request.user)

    try:
        # 调用API生成摘要
        summary = generate_summary(article.content)
        if not summary:
            return JsonResponse({'error': '生成摘要失败，请重试'}, status=500)

        return JsonResponse({'summary': summary})
    except Exception as e:
        logger.error(f"生成摘要时出错: {str(e)}")
        return JsonResponse({'error': '服务器内部错误'}, status=500)


@login_required
def article_statistical_summary(request, pk):
    article = get_object_or_404(Article, pk=pk, author=request.user)

    try:
        # 调用API生成统计汇总
        statistical_summary = generate_statistical_summary(article.content)
        if not statistical_summary:
            return JsonResponse({'error': '生成统计汇总失败，请重试'}, status=500)

        return JsonResponse({'statistical_summary': statistical_summary})
    except Exception as e:
        logger.error(f"生成统计汇总时出错: {str(e)}")
        return JsonResponse({'error': '服务器内部错误'}, status=500)


# post_manager/article/views.py
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Category, Article


@login_required
def category_detail(request, pk):
    # 获取当前用户的分类
    category = get_object_or_404(Category, pk=pk, author=request.user)

    # 获取该分类下的所有文章（包括子分类的文章）
    child_categories = category.get_descendants(include_self=True)
    articles = Article.objects.filter(
        category__in=child_categories,
        author=request.user,
        is_deleted=False
    ).order_by('-created_at')

    return render(request, 'article/category_detail.html', {
        'category': category,
        'articles': articles,
        'child_categories': child_categories
    })
