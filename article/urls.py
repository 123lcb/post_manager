from django.urls import path
from article.views import article_list, article_create, article_edit, article_delete, article_detail, share_article, share_article_detail, list_share

urlpatterns = [
    path('list/', article_list, name='article_list'),
    path('create/', article_create, name='article_create'),
    path('edit/<int:pk>/', article_edit, name='article_edit'),
    path('delete/<int:pk>/',article_delete, name='article_delete'),
    path('detail/<int:pk>/', article_detail, name='article_detail'),
    path('share/<int:pk>/', share_article, name='share_article'),
    path('share/detail/<int:pk>/', share_article_detail, name='share_article_detail'),
    path('list_share/', list_share, name='list_share'),
]
