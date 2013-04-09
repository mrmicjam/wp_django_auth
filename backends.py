__author__ = 'cristiroma'

from django.contrib.auth.models import User


class WPAuthenticationBackend(object):

    def authenticate(self, username=None, password=None):
        # http://stackoverflow.com/questions/13193278/understand-python-threading-bug
        import threading
        threading._DummyThread._Thread__stop = lambda x: 42

        import wp_django_auth as wp
        user = None
        (user_id, cookie_name, cookie) = wp.authenticate_user(username,
                                                              password)
        if user_id > 0:
            try:
                # Successful authentication in WordPress
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                pass
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    #@todo: Override has_perm and implement custom permissions
    #def has_perm(self, user_obj, perm):
    #    if user_obj.username == settings.ADMIN_LOGIN:
    #        return True
    #    else:
    #        return False
