# article/middleware.py
from django.utils.deprecation import MiddlewareMixin

class CategoryAuthorMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        # 对于分类视图，确保request.user可用
        if view_func.__name__ in ['category_create', 'category_edit']:
            if not request.user.is_authenticated:
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path())