#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

from subprocess import Popen, PIPE
import simplejson as json
import time
from django.http import HttpResponseRedirect
import hmac
import MySQLdb
import urllib
import hashlib

WP_DJANGO_SETTINGS = {
    'WP_HOME_DIR': '',
    'WP_URL': '',
    'WP_MYSQL_USER': '',
    'WP_MYSQL_PASSWD': '',
    'WP_MYSQL_DB': '',
    'WP_MYSQL_HOST': 'localhost',
    'WP_TABLE_PREFIX': 'wp_',
    ##OPTIONAL: Fill in values below from wp-config.php to avoid PHP calls
    'WP_LOGGED_IN_KEY': '',
    'WP_LOGGED_IN_SALT': '',
}

try:
    from django.conf import settings
    if hasattr(settings, 'WP_DJANGO_SETTINGS'):
        WP_DJANGO_SETTINGS = dict(WP_DJANGO_SETTINGS.items() +
                                  settings.WP_DJANGO_SETTINGS.items())
except ImportError:
    pass


class PHP:
    """ A class for calling PHP from Python """

    def __init__(self, prefix="", postfix=""):
        """
        Semicolons are not added automatically, so you'll need to make sure
        to put them in!
        :param prefix: optional prefix for all code (usually require statements)
        :param postfix: optional postfix for all code
        :return:
        """
        self.prefix = prefix
        self.postfix = postfix

    def __submit(self, code):
        p = Popen('php', shell=True, bufsize=4096, stdin=PIPE, stdout=PIPE,
                  close_fds=True)
        print >> p.stdin, "<?php "
        print >> p.stdin, self.prefix
        print >> p.stdin, code
        print >> p.stdin, self.postfix
        print >> p.stdin, " ?>"
        p.stdin.close()
        return p.stdout

    def get_raw(self, code):
        """
        Given a code block, invoke the code and return the raw result as string
        :param code: PHP code to execute
        :return: echoed output
        """
        out = self.__submit(code)
        return out.read()

    def get(self, code):
        """
        Given a code block that emits json, invoke the code and interpret the
        result as a Python value (JSON).
        :param code: PHP code to execute
        :return: JSON decoded output echoed by the script code
        """
        out = self.__submit(code)
        txt = out.read()
        return json.loads(txt)

    def get_one(self, code):
        """
        Given a code block that emits multiple json values (one per line),
        yield the next value.
        :param code: PHP code to execute
        :return: JSON decoded output echoed by the script code
        """
        out = self.__submit(code)
        for line in out:
            line = line.strip()
            if line:
                yield json.loads(line)

    def get_wp_security_tokens(self):
        """
        Returns the WordPress security tokens LOGGED_IN_KEY and LOGGED_IN_SALT
        :return: Tuple with WordPress configuration
        """
        global WP_DJANGO_SETTINGS
        if not (len(WP_DJANGO_SETTINGS['WP_LOGGED_IN_KEY']) and
                len(WP_DJANGO_SETTINGS['WP_LOGGED_IN_SALT'])):
            code = "echo json_encode(array('LOGGED_IN_SALT' => LOGGED_IN_SALT, \
            'LOGGED_IN_KEY' => LOGGED_IN_KEY, 'wp_version' => $wp_version));"
            ret = self.get(code)
            WP_DJANGO_SETTINGS['WP_LOGGED_IN_KEY'] = ret['LOGGED_IN_KEY']
            WP_DJANGO_SETTINGS['WP_LOGGED_IN_SALT'] = ret['LOGGED_IN_SALT']
        return (WP_DJANGO_SETTINGS['WP_LOGGED_IN_KEY'],
                WP_DJANGO_SETTINGS['WP_LOGGED_IN_SALT'])


def uses_php_bridge(func):
    """
    Decorator that passes a PHP Bridge object with some standard
    WordPress includes
    :param func: Wrapped function
    :return: Decorated function
    """
    def wrap(*args, **kwargs):
        oPHP = kwargs.get("oPHP", None)
        if not oPHP:
            global WP_DJANGO_SETTINGS
            oPHP = PHP("""
              require '%s/wp-load.php';
              require '%s/wp-includes/pluggable.php';
              require '%s/wp-includes/registration.php';
              """ % (WP_DJANGO_SETTINGS['WP_HOME_DIR'],
                     WP_DJANGO_SETTINGS['WP_HOME_DIR'],
                     WP_DJANGO_SETTINGS['WP_HOME_DIR']))
        kwargs["oPHP"] = oPHP
        return func(*args, **kwargs)

    return wrap


@uses_php_bridge
def authenticate_user(username, password, oPHP=None):
    """ RETURNS THE USER ID AND THE LOGGED IN COOKIE TO AUTHENTICATE AGAINST """
    code = """
    $user_id =  wp_authenticate('%s', '%s')->ID;
    echo json_encode($user_id);
    //$cookie = wp_generate_auth_cookie($user_id, %%s, 'logged_in');
    //$a = array($user_id, $cookie);
    //echo json_encode($a);
    """ % (username, password)
    try:
        user_id = int(oPHP.get(code))
    except:
        user_id = 0
    cookie_name, cookie = generate_cookie(user_id)
    return [user_id, cookie_name, cookie]


@uses_php_bridge
def register_user(username, password, email, oPHP=None):
    """RETURNS THE NEWLY CREATED USER_ID WITH AUTH STRING, OR 0, WITH MESSAGE"""
    code = """
    if (username_exists('%s')){
        $a = array(0, "Username already registered");
        echo json_encode($a);
    } else {
        if (email_exists('%s')){
            $a = array(0, "Email already registered");
            echo json_encode($a);
        } else {
            if (!validate_username('%s')){
                $a = array(0, "Invalid Username");
                echo json_encode($a);
            } else {
                //MADE IT THIS FAR, LETS REGISTER THIS BAD BOY
                $user_data = array('user_login'=>'%s', 'user_pass'=>'%s',
                    'user_email'=>'%s');
                $user_id = wp_insert_user($user_data);
                $cookie = wp_generate_auth_cookie($user_id, %s, 'logged_in');
                $a = array($user_id, $cookie);
                echo json_encode($a);
            }
        }
    }
    """ % (username, email, username, username, password, email,
           int(time.time() + 5000))
    return oPHP.get(code)


@uses_php_bridge
def reset_password(user_id, new_password, oPHP=None):
    """SETS A NEW PASSWORD, RETURNS USER_ID ON SUCCESS"""
    code = """
        wp_set_password('%s', %s);
        $a = array(1);
        echo json_encode($a);
    """ % (new_password, user_id)
    return oPHP.get(code)


def get_wp_user(func):
    """
    decorator that passes the current authenticated user_id to a function
    :param func: Wrapped function
    :return: Decorated function
    """
    def wrap(request, *args, **kwargs):
        user_id = 0
        cursor = None
        cookie = ""
        for cookie_name in request.COOKIES.keys():
            if "wordpress_logged_in_" in cookie_name:
                cookie = request.COOKIES[cookie_name]

        wp_user = auth_cookie(cookie)

        kwargs["wp_user"] = wp_user

        return func(request, *args, **kwargs)


    return wrap


@uses_php_bridge
def generate_cookie(user_id, oPHP=None):
    """
    Creates a logged_in cookie from a user_id
    :param user_id: WordPress user ID
    :param oPHP: (Optional) PHP bridge
    :return: List with cookie name and cookie
    """
    if not user_id:
        return ["", ""]
    cursor = None
    try:
        global WP_DJANGO_SETTINGS
        db = MySQLdb.connect(
            host=WP_DJANGO_SETTINGS['WP_MYSQL_HOST'],
            user=WP_DJANGO_SETTINGS['WP_MYSQL_USER'],
            passwd=WP_DJANGO_SETTINGS['WP_MYSQL_PASSWD'],
            db=WP_DJANGO_SETTINGS['WP_MYSQL_DB'])
        cursor = db.cursor()

        #Get the password slice
        cursor.execute(
            "select user_login, user_pass from %susers where ID = %s" % (
                WP_DJANGO_SETTINGS['WP_TABLE_PREFIX'], '%s'), (user_id, ))
        username, user_pass = cursor.fetchone()
        username = username.replace("+", " ")
        user_pass_slice = user_pass[8:12]

        expire = str(int(time.time() + 5000))
        logged_in_key, logged_in_salt = oPHP.get_wp_security_tokens()
        hmac_key = hmac.new(logged_in_key + logged_in_salt,
                            username + user_pass_slice + "|" + expire)
        hmac_to_match = hmac.new(hmac_key.hexdigest(), username + "|" + expire)
        to_match = hmac_to_match.hexdigest()

        #username, expire, raw_hash = urllib.unquote(cookie).split("|")
        cookie = "%s|%s|%s" % (username.replace(" ", "+"), expire, to_match)
    finally:
        if cursor:
            cursor.close()
    cookie_hash = hashlib.md5(WP_DJANGO_SETTINGS['WP_URL'])
    cookie_name = "wordpress_logged_in_" + cookie_hash.hexdigest()
    return [cookie_name, cookie]


@uses_php_bridge
def auth_cookie(cookie, oPHP=None):
    """
    authenticates a cookie
    :param cookie: Cookie to authenticate
    :param oPHP: (Optional) PHP bridge
    :return: WPUser object
    """
    user_id = 0
    cursor = None
    try:
        if cookie:
            global WP_DJANGO_SETTINGS
            db = MySQLdb.connect(
                host=WP_DJANGO_SETTINGS['WP_MYSQL_HOST'],
                user=WP_DJANGO_SETTINGS['WP_MYSQL_USER'],
                passwd=WP_DJANGO_SETTINGS['WP_MYSQL_PASSWD'],
                db=WP_DJANGO_SETTINGS['WP_MYSQL_DB'])
            cursor = db.cursor()
            username, expire, raw_hash = urllib.unquote(cookie).split("|")

            if int(expire) >= time.time():
                #Get the password slice
                username = username.replace("+", " ")
                cursor.execute(
                    "select ID, user_pass from %susers where user_login = %s" %
                    (WP_DJANGO_SETTINGS['WP_TABLE_PREFIX'], '%s'), (username, ))
                to_return_id, user_pass = cursor.fetchone()
                user_pass_slice = user_pass[8:12]
                logged_in_key, logged_in_salt = oPHP.get_wp_security_tokens()
                hmac_key = hmac.new(logged_in_key + logged_in_salt,
                                    username + user_pass_slice + "|" + expire)
                hmac_to_match = hmac.new(hmac_key.hexdigest(),
                                         username + "|" + expire)
                to_match = hmac_to_match.hexdigest()
                if to_match == raw_hash:
                    user_id = to_return_id
    finally:
        if cursor:
            cursor.close()

    class WPUser:
        def __init__(self, user_id=0, user_name=""):
            self.user_id = user_id
            self.user_name = user_name

    if user_id:
        wp_user = WPUser(user_id, username)
    else:
        wp_user = WPUser()#blank one

    return wp_user


class wp_login_redirect(object):
    """
    redirects to login/registration orm on login required,
    redirects back on success
    """

    def __init__(self, login_url="/registration/login_register"):
        """
        If there are decorator arguments, the function
        to be decorated is not passed to the constructor!
        """
        self.login_url = login_url

    def __call__(self, f):
        """
        If there are decorator arguments, __call__() is only called
        once, as part of the decoration process! You can only give
        it a single argument, which is the function object.
        """

        def wrap(request, *args, **kwargs):
            wp_user = kwargs[
                "wp_user"]  #@get_wp_user NEEDS TO BE CALLED BEFORE THIS
            if not wp_user.user_id:
                #THS CHUMP AIN'T LOGGED IN, LOGIN FORM HIM

                full_path = request.get_full_path()
                login_form_url = "%s?red=%s" % (self.login_url, full_path)

                return HttpResponseRedirect(login_form_url)
            else:
                return f(request, *args, **kwargs)

        return wrap


def test():
    """
    Run functional tests
    :return: None
    """

    ##MAKE SURE THESE SUCCEED
    #TEST REGISTERING A NEW USER
    import random


    new_username = "".join(random.sample("abcdefghijklmnop123456789_", 10))
    new_password = "".join(random.sample("abcdefghijklmnop123456789_", 10))
    user_id, cookie = register_user(new_username, new_password,
                                    "%s@example.com" % new_username)
    #THIS COOKIE DOESN'T WORK FOR RE-AUTH FOR SOME REASON UNKNOWN...
    cookie_name, cookie = generate_cookie(user_id)
    assert (user_id)

    #MAKE SURE THE RETURNED COOKIE AUTHENTICATES ON ITS OWN AND THE INFO MATCHES
    wp_user = auth_cookie(cookie)
    assert (user_id == wp_user.user_id)
    assert (new_username == wp_user.user_name)

    #TEST LOGGING IN THE USER WE JUST AUTHENTICATED
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username,
                                                           new_password)
    assert (c_user_id)
    assert (c_user_id == user_id)

    #MAKE SURE THE RETURNED COOKIE AUTHENTICATES ON ITS OWN AND THE INFO MATCHES
    wp_user = auth_cookie(c_cookie)
    assert (user_id == wp_user.user_id)
    assert (new_username == wp_user.user_name)

    #CHANGE THE PASSWORD FOR THIS NEW USER.
    new_reset_password = "".join(
        random.sample("abcdefghijklmnop123456789_", 10))
    c_user_id = reset_password(user_id, new_reset_password)
    assert (c_user_id)

    ##TRY TO LOG IN AGAIN WITH THE NEW PASSWORD
    #FIRST MAKE SURE THE OLD PASSWORD DOESN'T WORK
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username,
                                                           new_password)
    assert (c_user_id == 0)

    #NOW USE THE NEW PASSWORD
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username,
                                                           new_reset_password)
    assert (c_user_id)
    assert (c_user_id == user_id)

    print "All tests succeeded. Test account %s from your WP admin" % \
          new_username


if __name__ == "__main__":
    test()
