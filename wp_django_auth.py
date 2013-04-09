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

import popen2
import simplejson as json
import time
from django.http import HttpResponseRedirect
import hmac
import MySQLdb
import urllib
import md5 as hashlib


##REQUIRED PARAMETERS FOR THIS TO WORK
WP_HOME_DIR = '/var/www/html'
WP_URL = "http://www.example.org"
WP_MYSQL_USER="mysql_user"
WP_MYSQL_PASSWD="password"
WP_MYSQL_DB="mysql_db"
WP_MYSQL_HOST="localhost"
WP_TABLE_PRFIX='wp_'

##OPTIONAL OPTIMIZATION: GET THIS VALUE FROM wp-config.php so I don't have to call PHP on every auth to get it "define('LOGGED_IN_KEY', '**THIS VALUE**');"
LOGGED_IN_KEY = ''
LOGGED_IN_SALT = ''

#---------------------------------------
# A class for calling PHP from Python
#---------------------------------------  
class PHP:
    """This class provides a stupid simple interface to PHP code."""

    def __init__(self, prefix="", postfix=""):
        """prefix = optional prefix for all code (usually require statements)
        postfix = optional postfix for all code
        Semicolons are not added automatically, so you'll need to make sure to put them in!"""

        self.prefix = prefix
        self.postfix = postfix

    def __submit(self, code):
        (out, inp) = popen2.popen2("php")
        print >>inp, "<?php "
        print >>inp, self.prefix
        print >>inp, code
        print >>inp, self.postfix
        print >>inp, " ?>"
        inp.close()
        return out

    def get_raw(self, code):
        """Given a code block, invoke the code and return the raw result as a string."""
        out = self.__submit(code)
        return out.read()

    def get(self, code):
        """Given a code block that emits json, invoke the code and interpret the result as a Python value."""
        out = self.__submit(code)
        txt = out.read()
        return json.loads(txt)

    def get_one(self, code):
        """Given a code block that emits multiple json values (one per line), yield the next value."""
        out = self.__submit(code)
        for line in out:
            line = line.strip()
            if line:
                yield json.loads(line)

    def get_wp_security_tokens(self):
        """ Returns the WordPress security tokens LOGGED_IN_KEY and LOGGED_IN_SALT """
        if LOGGED_IN_KEY and LOGGED_IN_SALT:
            logged_in_key = LOGGED_IN_KEY
            logged_in_salt = LOGGED_IN_SALT
        else:
            code = "echo json_encode(array('LOGGED_IN_SALT' => LOGGED_IN_SALT, 'LOGGED_IN_KEY' => LOGGED_IN_KEY, 'wp_version' => $wp_version));"
            ret = self.get(code)
            logged_in_key = ret['LOGGED_IN_KEY']
            logged_in_salt = ret['LOGGED_IN_SALT']
        return (logged_in_key, logged_in_salt)
     
#---------------------------------------
# decorator that passes a PHP Bridge object
# with some standard wordpress includes
#---------------------------------------           
def uses_php_bridge(func):
    def wrap(*args, **kwargs):
        oPHP = kwargs.get("oPHP", None)
        if not oPHP:
            oPHP = PHP("""
              require '%s/wp-load.php';
              require '%s/wp-includes/pluggable.php';
              require '%s/wp-includes/registration.php';
              """ % (WP_HOME_DIR, WP_HOME_DIR, WP_HOME_DIR))
        kwargs["oPHP"] = oPHP
        return func(*args, **kwargs)
    return wrap
                
#---------------------------------------
# returns a user_id and cookie from
# a username and password
#---------------------------------------
@uses_php_bridge
def authenticate_user(username, password, oPHP=None):
    """RETURNS THE USER ID AND THE LOGGED IN COOKIE TO AUTHENTICATE AGAINST"""
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

#---------------------------------------
# registers a new user given a username, password, and email
# returns a user_id and cookie
#---------------------------------------
@uses_php_bridge
def register_user(username, password, email, oPHP=None):
    """RETURNS THE NEWSLY CREATED USER_ID WITH AUTH STRING, OR 0, WITH MESSAGE"""
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
                $user_data = array('user_login'=>'%s', 'user_pass'=>'%s', 'user_email'=>'%s');
                $user_id = wp_insert_user($user_data);
                $cookie = wp_generate_auth_cookie($user_id, %s, 'logged_in');
                $a = array($user_id, $cookie);
                echo json_encode($a);
            }
        }
    }
    """ % (username, email, username, username, password, email, int(time.time() + 5000))
    return oPHP.get(code)

#---------------------------------------
# resets the password of the given user_id
#---------------------------------------
@uses_php_bridge
def reset_password(user_id, new_password, oPHP=None):
    """SETS A NEW PASSWORD, RETURNS USER_ID ON SUCCESS"""
    code = """
        wp_set_password('%s', %s);
        $a = array(1);
        echo json_encode($a);
    """ % (new_password, user_id)
    return oPHP.get(code)


#---------------------------------------
# decorator that passes the current authenticated
# user_id to a function
#---------------------------------------
def get_wp_user(func):
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


#---------------------------------------
# creates a logged_in cookie from a user_id
#---------------------------------------
@uses_php_bridge
def generate_cookie(user_id, oPHP = None):
    cookie = ""
    if not user_id:
        return ["", ""]
    try:
        db = MySQLdb.connect(host=WP_MYSQL_HOST, user=WP_MYSQL_USER, passwd=WP_MYSQL_PASSWD, db=WP_MYSQL_DB)
        cursor = db.cursor()   
        
        #Get the password slice
        cursor.execute("select user_login, user_pass from %susers where ID = %s", (WP_TABLE_PRFIX, user_id, ))
        username, user_pass = cursor.fetchone()
        username = username.replace("+", " ")
        user_pass_slice = user_pass[8:12]
        
        expire = str(int(time.time() + 5000))
        logged_in_key, logged_in_salt = oPHP.get_wp_security_tokens()
        hmac_key = hmac.new(logged_in_key + logged_in_salt, username + user_pass_slice + "|" + expire)
        hmac_to_match = hmac.new(hmac_key.hexdigest(), username + "|" + expire)
        to_match = hmac_to_match.hexdigest()

        #username, expire, raw_hash = urllib.unquote(cookie).split("|")
        cookie = "%s|%s|%s" % (username.replace(" ", "+"), expire, to_match)
    finally:
        if cursor: cursor.close()
    cookie_hash = hashlib.md5(WP_URL)
    cookie_name = "wordpress_logged_in_" + cookie_hash.hexdigest()
    return [cookie_name, cookie]

#---------------------------------------
# authenticates a cookie
#---------------------------------------
@uses_php_bridge
def auth_cookie(cookie, oPHP = None):
    user_id = 0
    cursor = None
    try:
        if cookie:
            db = MySQLdb.connect(host=WP_MYSQL_HOST, user=WP_MYSQL_USER, passwd=WP_MYSQL_PASSWD, db=WP_MYSQL_DB)
            cursor = db.cursor()    
            username, expire, raw_hash = urllib.unquote(cookie).split("|")
            
            if int(expire) >= time.time():
                #Get the password slice
                username = username.replace("+", " ")
                cursor.execute("select ID, user_pass from %susers where user_login = %s", (WP_TABLE_PRFIX, username, ))
                to_return_id, user_pass = cursor.fetchone()
                user_pass_slice = user_pass[8:12]
                logged_in_key, logged_in_salt = oPHP.get_wp_security_tokens()
                hmac_key = hmac.new(logged_in_key + logged_in_salt, username + user_pass_slice + "|" + expire)
                hmac_to_match = hmac.new(hmac_key.hexdigest(), username + "|" + expire)
                to_match = hmac_to_match.hexdigest() 
                if to_match == raw_hash:
                    user_id = to_return_id
    finally:
        if cursor: cursor.close()
        
    class WPUser:
        def __init__(self, user_id = 0, user_name = ""):
            self.user_id = user_id
            self.user_name = user_name
        
    if user_id:
        wp_user = WPUser(user_id, username)
    else: wp_user = WPUser()#blank one
    
    return wp_user

#---------------------------------------
# redirects to login/registration orm on
# login required, redirects back on success
#---------------------------------------
class wp_login_redirect(object):
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
            wp_user = kwargs["wp_user"]  #@get_wp_user NEEDS TO BE CALLED BEFORE THIS
            if not wp_user.user_id:
                #THS CHUMP AIN'T LOGGED IN, LOGIN FORM HIM
                    
                full_path = request.get_full_path()
                login_form_url = "%s?red=%s" % (self.login_url, full_path)
                    
                return HttpResponseRedirect(login_form_url)
            else:
                return f(request, *args, **kwargs)

        return wrap


def test():
    ##MAKE SURE THESE SUCCEED
    #TEST REGISTERING A NEW USER
    import random
    new_username = "".join(random.sample("abcdefghijklmnop123456789_", 10))
    new_password = "".join(random.sample("abcdefghijklmnop123456789_", 10))
    user_id, cookie = register_user(new_username, new_password, "%s@example.com" % new_username) #THIS COOKIE DOESN'T WORK FOR RE-AUTH FOR SOME REASON UNKNOWN...
    cookie_name, cookie = generate_cookie(user_id)
    assert(user_id)
    
    #MAKE SURE THE RETURNED COOKIE AUTHENTICATES ON ITS OWN AND THE INFO MATCHES
    wp_user = auth_cookie(cookie)
    assert(user_id == wp_user.user_id)
    assert(new_username == wp_user.user_name)
    
    #TEST LOGGING IN THE USER WE JUST AUTHENTICATED
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username, new_password)
    assert(c_user_id)
    assert(c_user_id == user_id)
    
    #MAKE SURE THE RETURNED COOKIE AUTHENTICATES ON ITS OWN AND THE INFO MATCHES
    wp_user = auth_cookie(c_cookie)
    assert(user_id == wp_user.user_id)
    assert(new_username == wp_user.user_name)
    
    #CHANGE THE PASSWORD FOR THIS NEW USER.
    new_reset_password = "".join(random.sample("abcdefghijklmnop123456789_", 10))
    c_user_id = reset_password(user_id, new_reset_password)
    assert(c_user_id)
    
    ##TRY TO LOG IN AGAIN WITH THE NEW PASSWORD
    #FIRST MAKE SURE THE OLD PASSWORD DOESN'T WORK
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username, new_password)
    assert(c_user_id == 0)
    
    #NOW USE THE NEW PASSWORD
    c_user_id, c_cookie_name, c_cookie = authenticate_user(new_username, new_reset_password)
    assert(c_user_id)
    assert(c_user_id == user_id)
    
    
    print "All tests succeeded. you will need to the test account %s from your wordpress admin" % new_username
    
    

if __name__ == "__main__":
    test()
