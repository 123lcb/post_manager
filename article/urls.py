from django.urls import path

from article import views
from article.views import article_list, article_create, article_edit, article_delete, article_detail, share_article, share_article_detail, list_share
from .views import article_detail, article_summary, article_statistical_summary
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from .views import category_detail  # 导入视图

urlpatterns = [
    path('list/', article_list, name='article_list'),
    path('create/', article_create, name='article_create'),
    path('edit/<int:pk>/', article_edit, name='article_edit'),
    path('delete/<int:pk>/',article_delete, name='article_delete'),
    path('detail/<int:pk>/', article_detail, name='article_detail'),
    path('share/<int:pk>/', share_article, name='share_article'),
    path('share/detail/<int:pk>/', share_article_detail, name='share_article_detail'),
    path('list_share/', list_share, name='list_share'),
# 回收站路由
    path('trash/', views.trash_list, name='trash_list'),
    path('trash/restore/<int:pk>/', views.restore_article, name='restore_article'),
    path('trash/delete/<int:pk>/', views.permanent_delete, name='permanent_delete'),
    path('trash/empty/', views.empty_trash, name='empty_trash'),
    path('categories/', views.category_list, name='category_list'),
    path('categories/create/', views.category_create, name='category_create'),
    path('categories/edit/<int:pk>/', views.category_edit, name='category_edit'),
    path('categories/delete/<int:pk>/', views.category_delete, name='category_delete'),
    path('ajax/create-category/', views.ajax_create_category, name='ajax_create_category'),
    path('<int:pk>/', article_detail, name='article_detail'),
    path('<int:pk>/summary/', article_summary, name='article_summary'),
    path('<int:pk>/statistical-summary/', article_statistical_summary, name='article_statistical_summary'),
    path('category/<int:pk>/', category_detail, name='category_detail'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)