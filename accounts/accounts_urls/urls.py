from django.urls import path
from accounts.views import register, login_view, image_code, send_verification_code, index ,user_info ,verify_email_change ,send_password_reset_code ,reset_password_with_code
from accounts.views import logout_view, password_reset, password_reset_confirm

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('image_code/', image_code, name='image_code'),
    path('send_verification_code/', send_verification_code, name='send_verification_code'),
    path('index/', index, name='index'),
    path('user_info/', user_info, name='user_info'),
    path('verify_email_change/', verify_email_change, name='verify_email_change'),
    # path('home/', home, name='home'),
    path('send_password_reset_code/', send_password_reset_code, name='send_password_reset_code'),
    path('reset_password_with_code/', reset_password_with_code, name='reset_password_with_code'),
    path('password_reset/', password_reset, name='password_reset'),
    path('password_reset_confirm/', password_reset_confirm, name='password_reset_confirm'),
]
