from captcha.models import CaptchaStore
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.db.models import Q
from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from django.core.mail import send_mail
from django.conf import settings
from .forms import RegisterForm, LoginForm, generate_verification_code
from .code import check_code
from io import BytesIO
import json
import os
from .models import Favorite  # 导入收藏模型
from article.models import ShareArticle  # 导入文章模型

from django.core.cache import cache

def image_code(request):
    """ Generate image verification code """
    img, code_string = check_code()
    
    # Store code in cache with 60s expiration
    cache_key = f"image_code_{request.session.session_key}"
    cache.set(cache_key, code_string, timeout=60)

    stream = BytesIO()
    img.save(stream, 'png')
    stream.getvalue()

    return HttpResponse(stream.getvalue())

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST, initial={'request': request})
        # Get user submitted verification code
        user_submitted_code = request.POST.get('image_code')
        # Verify code using cache
        cache_key = f"image_code_{request.session.session_key}"
        cached_code = cache.get(cache_key, '').strip().lower()
        user_code = (user_submitted_code or '').strip().lower()
        
        if not cached_code or user_code != cached_code:
            messages.error(request, '验证码错误或已过期')
            return render(request, 'register.html', {'form': form})
        
        # Clear used code
        cache.delete(cache_key)
        
        if form.is_valid():
            try:
                # print("表单数据验证通过:", form.cleaned_data)  # 调试日志
                user = form.save(commit=False)
                user.set_password(form.cleaned_data['password1'])
                user.save()
                # print(f"用户 {user.username} 注册成功，ID: {user.id}")  # 调试日志
                login(request, user)
                messages.success(request, '注册成功！欢迎加入我们。')
                return redirect('login')
            except Exception as e:
                # print(f"注册保存失败: {str(e)}")  # 调试日志
                messages.error(request, f'注册失败: {str(e)}')
                return render(request, 'register.html', {'form': form})
        else:
            # print("表单验证失败 - 错误详情:", form.errors)  # 详细错误日志
            # print("提交的数据:", request.POST)  # 记录原始提交数据
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return render(request, 'register.html', {'form': form})
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def send_verification_code(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            return HttpResponse(json.dumps({'status': 'error', 'message': '邮箱不能为空'}), 
                             content_type='application/json')
        
        # 生成验证码并存入session
        code = generate_verification_code().strip()
        print(f"生成验证码: {code}")  # 调试日志
        
        # 确保session保存
        request.session['email_verification_code'] = code
        request.session['email_verification_email'] = email.strip()
        request.session.modified = True  # 强制session保存
        request.session.set_expiry(300)  # 5分钟有效期
        
        # 验证session是否保存成功
        saved_code = request.session.get('email_verification_code', 'NOT SAVED')
        print(f"Session保存状态 - 验证码: {saved_code}, 邮箱: {request.session.get('email_verification_email', 'NOT SAVED')}")
        
        # 发送邮件
        try:
            send_mail(
                '您的注册验证码',
                f'您的验证码是: {code}，5分钟内有效',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return HttpResponse(json.dumps({'status': 'success', 'message': '验证码已发送'}),
                              content_type='application/json')
        except Exception as e:
            return HttpResponse(json.dumps({'status': 'error', 'message': str(e)}),
                              content_type='application/json')
    
    return HttpResponse(json.dumps({'status': 'error', 'message': '无效请求'}),
                      content_type='application/json')

from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from .forms import UserProfileForm
from .models import UserProfile
from django.core.files.storage import default_storage
from PIL import Image
from django.contrib.auth import get_user_model
from django.http import JsonResponse
import json

@login_required
def user_info(request):
    user_profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            # 只在有新头像上传时处理
            if 'avatar' in request.FILES:
                new_avatar = request.FILES['avatar']
                
                # 删除旧头像（如果存在）
                if user_profile.avatar:
                    try:
                        # 使用Django存储系统安全删除
                        old_avatar_path = user_profile.avatar.path
                        if default_storage.exists(old_avatar_path):
                            default_storage.delete(old_avatar_path)
                    except Exception as e:
                        print(f"删除旧头像失败: {e}")
                
                # 保存新头像
                user_profile.avatar = new_avatar
            
            # 保存所有表单数据
            form.save()
            messages.success(request, '个人信息更新成功')
            return redirect('user_info')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserProfileForm(instance=user_profile)
    
    context = {
        'form': form,
    }
    return render(request, 'user_info.html', context)

from article.models import ShareArticle
from django.db.models import Q
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from .models import UserProfile, UserActionLog
from article.models import ShareArticle

@user_passes_test(lambda u: u.is_superuser)
def account_management(request):
    """账号管理视图"""
    search_query = request.GET.get('q', '')
    users = User.objects.all()
    
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(profile__nickname__icontains=search_query)
        )
    
    # 预加载profile数据减少查询
    users = users.select_related('profile')
    
    context = {
        'users': users,
        'search_query': search_query
    }
    return render(request, 'account_management.html', context)

@user_passes_test(lambda u: u.is_superuser)
def toggle_freeze_account(request, user_id):
    """冻结/解冻账号"""
    if request.method == 'POST':
        try:
            user = User.objects.get(pk=user_id)
            profile = user.profile
            reason = request.POST.get('reason', '')
            
            # 记录操作日志
            if profile.is_frozen:
                action = 'UNFREEZE'
                message = f'已解冻账号 {user.username}'
            else:
                action = 'FREEZE'
                message = f'已冻结账号 {user.username}'
            
            UserActionLog.objects.create(
                admin=request.user,
                user=user,
                action=action,
                reason=reason
            )
            
            # 切换冻结状态
            profile.is_frozen = not profile.is_frozen
            profile.save()
            
            messages.success(request, message)
        except Exception as e:
            messages.error(request, f'操作失败: {str(e)}')
    
    return redirect('account_management')

@user_passes_test(lambda u: u.is_superuser)
def action_logs(request):
    """操作记录查询"""
    logs = UserActionLog.objects.all().select_related('admin', 'user')
    return render(request, 'action_logs.html', {'logs': logs})

def index(request):
    """首页视图"""
    # 获取共享文章，按创建时间倒序排列，过滤已删除和已下架的文章
    shared_articles = ShareArticle.objects.filter(
        is_deleted=False, 
        is_removed=False
    ).order_by('-created_at')
    
    context = {
        'user': request.user,
        'is_authenticated': request.user.is_authenticated,
        'shared_articles': shared_articles  # 添加共享文章数据
    }
    return render(request, 'index.html', context)

def search_articles(request):
    """搜索文章视图"""
    query = request.GET.get('q', '')
    author = request.GET.get('author', '')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # 获取共享文章，过滤已删除和已下架的文章
    articles = ShareArticle.objects.filter(
        is_deleted=False,
        is_removed=False
    )
    
    # 应用搜索查询
    if query:
        articles = articles.filter(
            Q(title__icontains=query) |
            Q(plain_content__icontains=query))
    
    # 应用作者查询
    if author:
        articles = articles.filter(
            Q(author__username__icontains=author))
    
    # 应用日期范围过滤
    if start_date:
        articles = articles.filter(created_at__gte=start_date)
    if end_date:
        # 将结束日期加1天，以包含当天所有文章
        from datetime import datetime, timedelta
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        articles = articles.filter(created_at__lt=end_date_obj.strftime('%Y-%m-%d'))
    
    # 按创建时间倒序排列
    articles = articles.order_by('-created_at')
    
    context = {
        'articles': articles,
        'query': query,
        'start_date': start_date,
        'end_date': end_date,
        'is_authenticated': request.user.is_authenticated
    }
    return render(request, 'search_results.html', context)

    
def password_reset(request):
    """密码重置视图"""
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            messages.error(request, '邮箱不能为空')
            return render(request, 'password_reset.html')
        
        # 生成验证码并存入session
        from .forms import generate_verification_code
        code = generate_verification_code().strip()
        request.session['password_reset_code'] = code
        request.session['password_reset_email'] = email.strip()
        request.session.modified = True  # 强制session保存
        request.session.set_expiry(300)  # 5分钟有效期
        
        # 发送邮件
        try:
            send_mail(
                '您的密码重置验证码',
                f'您正在重置账户密码，验证码是: {code}，5分钟内有效',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            messages.success(request, '验证码已发送，请检查您的邮箱')
            return redirect('password_reset_confirm')
        except Exception as e:
            messages.error(request, f'发送验证码失败: {str(e)}')
            return render(request, 'password_reset.html')
    
    return render(request, 'password_reset.html')


def password_reset_confirm(request):
    """密码重置确认视图"""
    if request.method == 'POST':
        code = request.POST.get('code')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # 验证码验证
        session_code = request.session.get('password_reset_code', '')
        session_email = request.session.get('password_reset_email', '')
        
        if not session_code:
            messages.error(request, '验证码已过期，请重新获取')
            return redirect('password_reset')
            
        if code.strip().lower() != session_code.strip().lower():
            messages.error(request, '验证码错误')
            return render(request, 'password_reset_confirm.html')
        
        if new_password != confirm_password:
            messages.error(request, '两次输入的密码不一致')
            return render(request, 'password_reset_confirm.html')
        
        if len(new_password) < 8:
            messages.error(request, '密码长度至少为8位')
            return render(request, 'password_reset_confirm.html')
        
        # 更新用户密码
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            user = User.objects.get(email=session_email)
            user.set_password(new_password)
            user.save()
            
            # 清除session
            del request.session['password_reset_code']
            del request.session['password_reset_email']
            
            messages.success(request, '密码重置成功，请使用新密码登录')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, '该邮箱未注册')
            return redirect('password_reset')
    
    return render(request, 'password_reset_confirm.html')

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        # Get user submitted verification code
        user_submitted_code = request.POST.get('image_code')
        # Verify code using cache
        cache_key = f"image_code_{request.session.session_key}"
        cached_code = cache.get(cache_key, '').strip().lower()
        user_code = (user_submitted_code or '').strip().lower()
        
        if not cached_code or user_code != cached_code:
            messages.error(request, '验证码错误或已过期')
            return render(request, 'login.html', {'form': form})
        
        # Clear used code
        cache.delete(cache_key)
        
        username = request.POST.get('username')
        # 基于用户名+IP地址锁定，实现设备级锁定
        client_ip = request.META.get('REMOTE_ADDR', '')
        cache_key = f'login_failures_{username.lower().strip()}_{client_ip}'
        failures = cache.get(cache_key, 0)
        
        # 检查是否被锁定
        if failures >= 5:
            last_attempt = cache.get(f'{cache_key}_time')
            if last_attempt and timezone.now() < last_attempt + timedelta(minutes=5):
                remaining_time = (last_attempt + timedelta(minutes=5)) - timezone.now()
                minutes = remaining_time.seconds // 60
                seconds = remaining_time.seconds % 60
                msg = f'您的账号已被锁定，请{minutes}分{seconds}秒后再试'
                messages.error(request, msg)
                return render(request, 'login.html', {'form': form})
            else:
                # 锁定时间已过，重置计数器
                cache.delete(cache_key)
                failures = 0
        
        # 表单验证
        if not form.is_valid():
            failures += 1
            cache.set(cache_key, failures, 300)
            cache.set(f'{cache_key}_time', timezone.now(), 300)
            messages.error(request, '用户名或密码错误')
            return render(request, 'login.html', {'form': form})

        # 认证用户
        user = authenticate(username=form.cleaned_data['username'],
                          password=form.cleaned_data['password'])
        
        # 检查用户是否存在且未被冻结
        if user is None:
            failures += 1
            cache.set(cache_key, failures, 300)
            cache.set(f'{cache_key}_time', timezone.now(), 300)
            
            # 显示适当的错误消息
            if failures >= 5:
                msg = '您的账号已被锁定，请稍后再试'
                messages.error(request, msg)
            elif failures >= 3:
                msg = f'您还有{5-failures}次尝试机会'
                messages.warning(request, msg)
            else:
                msg = '用户名或密码错误'
                messages.error(request, msg)
            return render(request, 'login.html', {'form': form})
        elif hasattr(user, 'profile') and user.profile.is_frozen:
            messages.error(request, '您的账号已被冻结，请联系管理员')
            failures += 1
            cache.set(cache_key, failures, 300)
            cache.set(f'{cache_key}_time', timezone.now(), 300)
            return render(request, 'login.html', {'form': form})
        else:
            # 登录成功，清除失败计数
            cache.delete(cache_key)
            login(request, user)
            return redirect('index')  # 登录成功后重定向到个人信息页面

    # 处理GET请求
    form = LoginForm()
    return render(request, 'login.html', {'form': form})



@login_required
def logout_view(request):
    """退出登录视图"""
    logout(request)
    # 重定向到首页，确保返回HttpResponse对象
    return redirect('index')

@user_passes_test(lambda u: u.is_superuser)
def content_moderation(request):
    """内容审核视图"""
    # 处理批量操作
    if request.method == 'POST':
        # 获取选中的文章ID列表
        selected_ids = request.POST.getlist('selected_articles')
        action = request.POST.get('action')
        
        if not selected_ids:
            messages.warning(request, '请选择要操作的文章')
            return redirect('content_moderation')
        
        # 根据操作类型更新文章状态
        if action == 'remove':
            ShareArticle.objects.filter(id__in=selected_ids).update(is_removed=True)
            messages.success(request, f'已下架 {len(selected_ids)} 篇文章')
        elif action == 'restore':
            ShareArticle.objects.filter(id__in=selected_ids).update(is_removed=False)
            messages.success(request, f'已恢复 {len(selected_ids)} 篇文章')
    
    # 获取查询参数
    query = request.GET.get('q', '')
    status_filter = request.GET.get('status', 'all')
    
    # 获取所有共享文章
    articles = ShareArticle.objects.filter(is_deleted=False)
    
    # 应用查询过滤器
    if query:
        articles = articles.filter(
            Q(title__icontains=query) |
            Q(author__username__icontains=query)
        )
    
    # 应用状态过滤器
    if status_filter == 'removed':
        articles = articles.filter(is_removed=True)
    elif status_filter == 'active':
        articles = articles.filter(is_removed=False)
    
    # 按创建时间倒序排列
    articles = articles.order_by('-created_at')
    
    context = {
        'articles': articles,
        'query': query,
        'status_filter': status_filter
    }
    return render(request, 'content_moderation.html', context)

@login_required
def verify_email_change(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_email = data.get('email')
            code = data.get('code')
            
            # 验证码验证（不区分大小写并去除空格）
            session_code = (request.session.get('email_verification_code', '') or '').strip().lower()
            user_code = (code or '').strip().lower()
            
            # 调试日志
            print(f"Session验证码: {session_code}, 用户输入: {user_code}")
            
            if not session_code:
                return JsonResponse({'success': False, 'message': '验证码已过期，请重新获取'})
                
            if user_code != session_code:
                return JsonResponse({
                    'success': False, 
                    'message': '验证码错误',
                    'debug': {
                        'session_code': session_code,
                        'user_code': user_code
                    }
                })
            
            # 验证邮箱是否匹配
            session_email = request.session.get('email_verification_email', '')
            if new_email != session_email:
                return JsonResponse({'success': False, 'message': '邮箱不匹配'})
            
            # 更新用户邮箱
            User = get_user_model()
            user = request.user
            user.email = new_email
            user.save()
            
            # 清除session中的验证信息
            request.session.pop('email_verification_code', None)
            request.session.pop('email_verification_email', None)
            
            return JsonResponse({'success': True, 'message': '邮箱更新成功'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'更新失败: {str(e)}'})
    return JsonResponse({'success': False, 'message': '无效请求'})

# 在 views.py 中添加以下视图函数

@login_required
def send_password_reset_code(request):
    """发送密码重置验证码"""
    if request.method == 'POST':
        email = request.user.email
        if not email:
            return JsonResponse({'status': 'error', 'message': '未绑定邮箱，无法重置密码'})
        
        # 生成验证码并存入session
        code = generate_verification_code().strip()
        print(f"生成密码重置验证码: {code}")
        
        # 保存到session
        request.session['password_reset_code'] = code
        request.session['password_reset_email'] = email
        request.session.modified = True
        request.session.set_expiry(300)  # 5分钟有效期
        
        # 发送邮件
        try:
            send_mail(
                '您的密码重置验证码',
                f'您正在重置账户密码，验证码是: {code}，5分钟内有效',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return JsonResponse({'status': 'success', 'message': '验证码已发送'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    
    return JsonResponse({'status': 'error', 'message': '无效请求'})

@login_required
def reset_password_with_code(request):
    """使用验证码重置密码"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            code = data.get('code')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')
            
            # 验证密码一致性
            if new_password != confirm_password:
                return JsonResponse({
                    'success': False, 
                    'message': '两次输入的密码不一致'
                })
            
            # 验证密码长度
            if len(new_password) < 8:
                return JsonResponse({
                    'success': False, 
                    'message': '密码长度至少为8位'
                })
            
            # 验证验证码
            session_code = request.session.get('password_reset_code', '')
            session_email = request.session.get('password_reset_email', '')
            
            if not session_code:
                return JsonResponse({
                    'success': False, 
                    'message': '验证码已过期，请重新获取'
                })
                
            if code.strip().lower() != session_code.strip().lower():
                return JsonResponse({
                    'success': False, 
                    'message': '验证码错误'
                })
            
            # 验证邮箱是否匹配
            if request.user.email != session_email:
                return JsonResponse({
                    'success': False, 
                    'message': '邮箱不匹配'
                })
            
            # 更新用户密码
            user = request.user
            user.set_password(new_password)
            user.save()
            
            # 清除session中的验证信息
            request.session.pop('password_reset_code', None)
            request.session.pop('password_reset_email', None)
            
            return JsonResponse({
                'success': True, 
                'message': '密码重置成功'
            })
        except Exception as e:
            return JsonResponse({
                'success': False, 
                'message': f'密码重置失败: {str(e)}'
            })
    return JsonResponse({
        'success': False, 
        'message': '无效请求'
    })

@login_required
def favorites(request):
    """收藏列表视图"""
    # 获取当前用户的所有收藏文章
    favorites = Favorite.objects.filter(user=request.user).select_related('article')
    
    # 提取收藏的文章对象
    articles = [fav.article for fav in favorites]
    
    context = {
        'articles': articles,
        'is_authenticated': request.user.is_authenticated
    }
    return render(request, 'favorites.html', context)

@login_required
def add_favorite(request, article_id):
    """添加收藏视图"""
    try:
        # 获取文章对象
        article = ShareArticle.objects.get(pk=article_id, is_deleted=False, is_removed=False)
        
        # 检查是否已收藏
        if Favorite.objects.filter(user=request.user, article=article).exists():
            return JsonResponse({'success': False, 'message': '已收藏该文章'})
        
        # 创建收藏记录
        Favorite.objects.create(user=request.user, article=article)
        
        return JsonResponse({'success': True, 'message': '收藏成功'})
    except ShareArticle.DoesNotExist:
        return JsonResponse({'success': False, 'message': '文章不存在或已被删除'})

@login_required
def remove_favorite(request, article_id):
    """取消收藏视图"""
    try:
        # 获取收藏记录
        favorite = Favorite.objects.get(user=request.user, article_id=article_id)
        
        # 删除收藏记录
        favorite.delete()
        
        return JsonResponse({'success': True, 'message': '已取消收藏'})
    except Favorite.DoesNotExist:
        return JsonResponse({'success': False, 'message': '未收藏该文章'})
