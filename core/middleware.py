from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.utils.deprecation import MiddlewareMixin

class LoginRequiredMiddleware(MiddlewareMixin):
    """
    Simple middleware to require login for all views except a whitelist.
    This replaces the third-party 'django-login-required-middleware' package.
    """

    def _is_ignored(self, request):
        # ignore static/media paths
        if request.path.startswith(settings.STATIC_URL):
            return True

        # resolve view name if possible and check whitelist
        try:
            match = resolve(request.path_info)
            view_name = match.view_name
        except Exception:
            view_name = None

        ignore_names = getattr(settings, "LOGIN_REQUIRED_IGNORE_VIEW_NAMES", [])
        if view_name and view_name in ignore_names:
            return True

        # allow unauthenticated access to admin login and static files
        if request.path.startswith(reverse('admin:login', current_app=None)):
            return True

        return False

    def process_request(self, request):
        if not request.user.is_authenticated and not self._is_ignored(request):
            # redirect to login, preserving next
            login_url = reverse(settings.LOGIN_URL)
            return redirect(f"{login_url}?next={request.path}")
        return None
