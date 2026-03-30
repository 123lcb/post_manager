from django.urls import path
from accounts.views import (
    register, login_view, image_code, send_verification_code, index, user_info,
    verify_email_change, send_password_reset_code, reset_password_with_code,
    logout_view, password_reset, password_reset_confirm,
    account_management, toggle_freeze_account, action_logs, 
    content_moderation, search_articles,  # 内容审核视图和搜索视图
    favorites, add_favorite, remove_favorite  # 收藏功能视图
)

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('image_code/', image_code, name='image_code'),
    path('send_verification_code/', send_verification_code, name='send_verification_code'),
    path('index/', index, name='index'),
    path('user_info/', user_info, name='user_info'),
    path('verify_email_change/', verify_email_change, name='verify_email_change'),
    path('send_password_reset_code/', send_password_reset_code, name='send_password_reset_code'),
    path('reset_password_with_code/', reset_password_with_code, name='reset_password_with_code'),
    path('password_reset/', password_reset, name='password_reset'),
    path('password_reset_confirm/', password_reset_confirm, name='password_reset_confirm'),
    # 账号管理路由
    path('account_management/', account_management, name='account_management'),
    path('toggle_freeze/<int:user_id>/', toggle_freeze_account, name='toggle_freeze'),
    path('action_logs/', action_logs, name='action_logs'),
    # 内容审核
    path('content_moderation/', content_moderation, name='content_moderation'),
    path('search/', search_articles, name='search_articles'),
    # 收藏功能路由
    path('favorites/', favorites, name='favorites'),
    path('favorites/<int:article_id>/add/', add_favorite, name='add_favorite'),
    path('favorites/<int:article_id>/remove/', remove_favorite, name='remove_favorite'),
]
