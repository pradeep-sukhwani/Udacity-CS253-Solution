#  Whole project
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app
import webapp2

# Unit 2
import helper_functions as helper

# Unit 2 - Templates, Unit 3 to Unit 7
import os
import jinja2

# Unit 4
import random
import string
import hashlib
import hmac

# Unit 5, 6 - Homework
import json

# Unit 6 - Exercise & Homework
import time
import urllib2
import logging
from xml.dom import minidom
from google.appengine.api import memcache
from datetime import datetime, timedelta

### --->>> HOMEWORK UNIT - 1 <<<--- ###

unit1_form="""
<html>
<head>
    <title>Unit 1</title>
</head>
<body>
    <form method = post>
        Hello, Udacity!
    </form>

</body>
</html>
"""

### --->>> EXERCISE UNIT - 2 Birthday <<<--- ###

unit2_form_birthday="""
<form method="post">
    
    <head>
        <title>Unit 2 - Birthday</title>
    </head>

    <h1> What is your birthday? </h1>
    <label> <h4>Month</h4>
    <input type="text" name="month" value="%(month)s">
    </label>

    <label> <h4>Day</h4>
    <input type="text" name="day" value="%(day)s">
    </label>
    
    <label> <h4>Year</h4>
    <input type="text" name="year" value="%(year)s">
    </label>
    <div style="color: red">%(error)s</div>

    <br>
    <br>
    <label>Submit</label>
    <input type="submit">
</form>
"""
unit2_form_thanks="""
<form method="post">
    
    <head>
        <title>Unit 2 - Thanks</title>
    </head>

    That's atleast someone's birthday!! :)
</form>
"""

### --->>> HOMEWORK UNIT - 2 ROT13 <<<--- ###

unit2_form_rot_13="""
<form method="post">
    
    <head>
        <title>Unit 2 - Rot13</title>
    </head>
    <b>Enter some text to ROT13:</b>
    <br>

    <div>
        <textarea name="text" style="height: 100px; width: 500px;">%(user_input)s</textarea>
    </div>
    <br>

    <input type="submit">

</form>
"""

### --->>> HOMEWORK UNIT - 2 Signup Page <<<--- ###

unit2_form_username="""
<form method="post">
    
    <head>
        <title>Unit 2 - Sign Up</title>
    </head>

    <div>
    <h1>Signup</h>
    </div>

    <label> <b>Username</b>
    <input type="text" name="username" value="%(username)s">
    </label>
    <br>

    <div style="color: red">%(username_error)s</div>
    <br>

    <label> <b>Password</b>
    <input type ="password" name="password" value="%(password)s">
    </label>
    <br>

    <div style="color: red">%(password_error)s</div>
    <br>
    
    <label> <b>Verify Password</b>
    <input type="password" name="verifypassword" value="%(verify)s">
    </label>
    <br>

    <div style="color: red">%(verify_error)s</div>
    <br>

    <label> <b>Email</b>
    <input type="text" name="email" value="%(email)s">
    </label>
    <br>
    
    <div style="color: red">%(email_error)s</div>
    <br>

    <input type="submit">
</form>
"""

unit2_welcome="""
<form method="post">
    
    <head>
        <title>Unit 2 - Welcome</title>
    </head>

    <h2>Welcome, %(username)s!</h2>

</form>
"""

### --->>> Jinja Template <<<--- ###
# To import html file from the folder templates
# For Unit 2 Templates and Unit 3 to 7

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

### --->>> New Request Handler <<<--- ###

# For Unit 2 Templates and Unit 3 to 7

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # For Unit 5 Homework
    def render_json(self, blog_json):
        json_txt = json.dumps(blog_json)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    # For Unit 5 Homework
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

# For Unit 4

# In real life please keep this secret message separately in different file.
SECRET = "secret/secret/secret/secret/secret"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def hash_str(s): # using hmac
    return hmac.new(SECRET, s).hexdigest()

def encode(s): # converting to hmac and separating with a pipe (|)
               # as google app engine has some issue with comma(,)
    return "%s|%s" % (s, hash_str(s))

def decode(h):
    user_value = h.split('|')[0]
    if h == encode(user_value):
        return user_value

### --->>> HOMEWORK UNIT - 1 Handler <<<---###

class Unit1(webapp2.RequestHandler):
    def write_form(self):
        self.response.write(unit1_form)
    
    def get(self):
        self.write_form()

### --->>> Exercise UNIT - 2 Handler <<<---###

class Birthday(webapp2.RequestHandler):
    def write_form(self, error="", month="", day="", year=""):
        self.response.out.write(unit2_form_birthday % {"error": error,
                                        "month": month,
                                        "day": day,
                                        "year": year})

    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = helper.valid_month(user_month)
        day = helper.valid_day(user_day)
        year = helper.valid_year(user_year)
        
        if not (month and day and year):
            self.write_form("That's not even a vaild Date ): Please try again!!",
                            user_month, user_day, user_year)
        else:
            self.redirect("/unit2/thanks")

class Thanks(webapp2.RequestHandler):
    def write_form(self):
        self.response.out.write(unit2_form_thanks)

    def get(self):
        self.write_form()

### --->>> HOMEWORK UNIT - 2 ROT13 Handler <<<--- ###

class RotFunction(webapp2.RequestHandler):
    def write_form(self, form_input=""):
        self.response.write(unit2_form_rot_13 % {"user_input": helper.escape_html(form_input)})

    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write_form()

    def post(self):
        rot_input = self.request.get('text')
        rot_output = helper.rot13(rot_input)
        self.write_form(rot_output)

### --->>> HOMEWORK UNIT - 2 Signup Handler <<<--- ###

class SignUp(webapp2.RequestHandler):

    user_name_error = "That's not a valid username."
    pass_word_error = "That's not a valid password."
    verify_pass_error = "These passwords don't match. Try again?"
    user_email_error = "That's not a valid email."

    def write_form(self,username="",username_error="",password="",
                   password_error="", verify="",verify_error="",email="",email_error=""):
        self.response.out.write(unit2_form_username % {"username": helper.escape_html(username),
                                                "username_error": username_error,
                                                "password": helper.escape_html(password),
                                                "password_error": password_error,
                                                "verify": helper.escape_html(verify),
                                                "verify_error": verify_error,
                                                "email": helper.escape_html(email),
                                                "email_error": email_error})

    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write_form()

    def post(self):
        error_check = False
        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verifypassword')
        user_email = self.request.get('email')

        display_error_username = ""
        display_error_password = ""
        display_error_verify = ""
        display_error_email = ""
        
        if not helper.valid_username(user_name):
            display_error_username = self.user_name_error
            error_check = True

        if not helper.valid_password(user_password):
            display_error_password = self.pass_word_error
            error_check = True

        elif user_password != user_verify:
            display_error_verify = self.verify_pass_error
            error_check = True

        if not helper.valid_email(user_email):
            display_error_email = self.user_email_error
            error_check = True

        if error_check == True:
            self.write_form(username_error = display_error_username,
                            password_error = display_error_password,
                            verify_error = display_error_verify,
                            email_error = display_error_email)

        else:
            self.redirect("/unit2/welcome?username={}".format(user_name))
            # self.response.out.write("Welcome, {}!".format(user_name))

class Welcome(webapp2.RequestHandler):
    def write_form(self):
        username = self.request.get('username')
        self.response.out.write(unit2_welcome % {'username': username})

    def get(self):
        self.write_form()

### --->>> Exercise Unit - 2 Templates <<<---###

class Shopping(Handler):
    def get(self):
        items = self.request.get_all("food")
        self.render("shopping_list.html", items = items)

class FizzBuzz(Handler):
    def get(self):
        n = self.request.get('n', 0)
        n = n and int(n)
        self.render('fizzbuzz.html', n = n)

### --->>> Exercise Unit - 3 Handler ASCII <<<---###
### --->>> Exercise Unit - 5 Maps implementation <<<---###
### --->>> Exercise Unit - 6 Caching <<<---###

# Unit 5 - Map

MAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=520x300&sensor=false&key=AIzaSyAgZgYaIEjtUN8JBD9qb93rGAl5ZRVWU3A"
def maps_url(point):
    markers = '&'.join('markers=%s,%s' % (i.lat, i.lon)
        for i in point)
    return MAPS_URL + markers

IP_URL = 'http://freegeoip.net/xml/'

def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except urllib2.URLError:
        return

    if content:
        contents = minidom.parseString(content)
        lat = contents.getElementsByTagName("Latitude")[0].childNodes[0].nodeValue
        lon = contents.getElementsByTagName("Longitude")[0].childNodes[0].nodeValue
        if lat and lon:
            return db.GeoPt(lat, lon)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty() # Unit 5

# Unit 6
#cache = {} # a dictionary where all the cache as a key and vaule are stored
def fine_arts(update = False):
    key = 'top' # its just a normal value that is assigned to a variable key.
    arts = memcache.get(key)
    #if not update and key in cache:
        #logging.error('Non-DB Query')
    if arts is None or update:
        logging.error('DB Query')
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC Limit 10")

        # prevent the running of multiple queries
        arts = list(arts)
        memcache.set(key, arts)
    return arts

class AsciiArt(Handler):
    def render_front(self, title="", art="", error=""):
        arts = fine_arts()

        # Finds which arts has coords 
        point = []
        for i in arts:
            if i.coords:
                point.append(i.coords)
        #self.write(repr(point))
        
        # if any arts have coords, make an image url
        img_url = None
        if point:
            img_url = maps_url(point)

        # display the image
        self.render("ascii.html", title=title, art=art,
            error=error, arts=arts, img_url = img_url)

    def get(self):
        # Unit 5
        #self.write(self.request.remote_addr)
        #self.write(repr(get_coords(self.request.remote_addr)))
        self.render_front()

    def post(self):
        title = self.request.get('title')
        art = self.request.get('art')

        if title and art:
            a = Art(title = title, art = art)
            # Unit 5
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords
            a.put() # Unit 3
            time.sleep(1) # putting to sleep because even after adding files db then also it
            # need time to add the last requested file, thats why time.sleep function is used.
            #cache.clear() # need to clear the cache memory.
            
            # rerun the db and update the cache .
            fine_arts(True)

            self.redirect('/unit3/ascii')
        else:
            error = 'We need both a title and some artwork!'
            self.render_front(title, art, error)

### --->>> HOMEWORK UNIT - 3 Handler Create a blog <<<--- ###
### --->>> HOMEWORK UNIT - 5 json implemtation <<<--- ###
### --->>> HOMEWORK UNIT - 6 Caching <<<--- ###

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def blog_key(name = "default"):
    return db.Key.from_path('blogs', name)

### HOMEWORK UNIT - 6

def set_time(key, value):
    # sets the current time using utcnow python built-in function
    save_date_time = datetime.utcnow()
    # stores the time with the value in a tupe in cache i.e. memcache
    memcache.set(key, (value, save_date_time))

def get_time(key):
    result = memcache.get(key)
    if result:
        value, save_time = result
        # calculate the time in seconds using total_seconds python built-in
        # function in timedelta
        time = (datetime.utcnow() - save_time).total_seconds()
    else:
        value, time = None, 0
    return value, time

def add_post(post):
    post.put() # stores the post in database
    get_post(update = True) # This is used to override the value of cache with the
    # new value
    return str(post.key().id())

def get_posts(update = False):
    #results = Post.all().order('-created').fetch(limit = 10)
    results = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC Limit 10")
    mc_key = 'BLOGS' # memcache key

    post, time = get_time(mc_key)
    if update or post is None: # if update is true or posts aren't in the cache
    # run the query
        post = list(results) # runnning the query
        set_time(mc_key, post) # set the memcache key to value post
    
    return post, time

def second_str(time):
    time_second = 'queried for %s seconds ago'
    time = int(time) # convert time to integer
    if time <= 1:
        # if time is 0 or 1 second then it will return 0 second or 1 second
        time_second = time_second.replace('seconds', 'second')
    return time_second % time # string replacement

class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self.render_text = self.content.replace('\n', '<br>')
        return render_str('entries.html', p = self)

    # For unit 5 Homework
    def as_dict(self):
        # json implemtation creating dictionary
        time_fmt = '%c' # '%c' It normally gives the ascii value. But
        # here it caputures the time on which the post created.
        blog_json = {'subject': self.subject,
                     'content': self.content,
                     'created': self.created.strftime(time_fmt),
                     'last_modified': self.last_modified.strftime(time_fmt)}
        return blog_json

    def newpost_blog(self):
        # json implemtation creating dictionary
        blog_json = {'subject': self.subject,
                     'content': self.content}
        return blog_json

class NewPost(Handler):
    # New Post handler where subject and content to be submitted
    # def new_post(self, subject='', content='', error=''):
    #     self.render('newpost.html', subject=subject, content=content, error=error)

    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put() # To store the value in database
            self.redirect('/unit3/blog/%s' % str(p.key().id()))
        else:
            error = 'Need both subject and content!!'
            self.render('newpost.html', subject=subject, content=content,
                error = error)

class PermaLink(Handler):
    # Entries handler where newly added post can be seen only with date
    def get(self, post_id):
        # key for a particular post
        post_key = 'Post_' + post_id
        # check to see if their is a post and time in cache with a post_id
        post, time = get_time(post_key)

        # if post is not in cache, we run this query
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # set time to cache
            set_time(post_key, post)
            time = 0

        if not post:
        # it through an error if their is no post and you can mention
        # any error you want to display with the 404 to do that just write
        # the message afte the return.
            self.error(404)
            return

        # Unit 5 Homework
        # if post is in html it will render the newpost.html else post in json
        # format
        # if self.format == 'html':
        #     self.render("permalink.html", post = post)
        # else:
        #     self.render_json(post.as_dict())

        # Unit 6 Homework
        if self.format == 'html':
            self.render("permalink.html", post = post, time = second_str(time))
        else:
            self.render_json(post.as_dict())

    # def get(self):
    #     subject = self.request.get('subject')
    #     content = self.request.get('content')
        
    #     if subject and content:
    #         self.response.out.write("Subject")
    #         self.response.out.write("<br>")
    #         self.response.out.write(subject)
    #         self.response.out.write("<br>")
    #         self.response.out.write("<br>")
    #         self.response.out.write("content")
    #         self.response.out.write("<br>")
    #         self.response.out.write(content)
    #     else:
    #         self.redirect('/unit3/blog/newpost')

class Front(Handler, db.Model):
    # Front handler where all the posts can be seen with date
    def get(self):
        # For Unit 3
        #posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        #self.render('front.html', posts = posts)

        # For Unit 5 Homework
        # if self.format == 'html':
        #     self.render('front.html', posts = posts)
        # else:
        #     return self.render_json([p.as_dict() for p in posts])

        # Unit 6 Homework
        # calling get_posts() function, this returns the post and time
        posts, time = get_posts()

        # if post is in html it will render the newpost.html with post & time
        # else post in json format
        if self.format == 'html':
            self.render('front.html', posts = posts, time = second_str(time))
        else:
            return self.render_json([p.as_dict() for p in posts])

# Unit 6 Homework
class FlushHandler(Handler):
    # Flush the entire cache
    def get(self):
        memcache.flush_all()
        self.redirect("/unit3/blog")

### --->>> Exercise UNIT - 4 Handler Count Visits <<<--- ###

class VisitsHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Visits(VisitsHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        get_visits = self.request.cookies.get('visits')
        if get_visits:
            cookie_val = decode(get_visits)
            if cookie_val:
                visits = int(cookie_val)

        visits +=1

        new_visits = encode(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_visits)

        if visits <= 1:
            self.response.out.write("This page is just used for practice!! You've been here for %s time!" % visits)
        else:
            self.response.out.write("This page is just used for practice!! You've been here for %s times!" % visits)

### --->>> HOMEWORK UNIT - 4 Handler Set Cookie on SignUp Page <<<--- ###

class Unit4Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = encode(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name): # creating cookies and decoding
        cookie_val = self.request.cookies.get(name)
        return cookie_val and decode(cookie_val)

    def login(self, user): # this is used for registration
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
            'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def make_salt(length=5): # salting
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None): # hashing
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h): # hasing passwords
    ###Your code here
    salt = h.split('|')[0]
    return h == make_pw_hash(name, pw, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class SignUpHandler(Unit4Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not helper.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not helper.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not helper.valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self):
        raise NotImplementedError

class Register(SignUpHandler):
    def done(self, *a, **kw):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/unit4/welcome')

class Login(Unit4Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')

        u = User.login(self.username, self.password)
        if u:
            self.login(u)
            self.redirect('/unit4/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error_username = msg)

class Logout(Unit4Handler):
    def get(self):
        self.logout()
        self.redirect('/unit4/signup')
        

class Unit4Welcome(Unit4Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/unit4/signup')

class HomePage(Handler):
    """ This is home page where all links are defined """
    def get(self):
        self.render('home-page.html')
        

### --->>> HOMEWORK UNIT 5 - .json Implementation <<<--- ###
# It is implemented in unit 3 itself.

### --->>> HOMEWORK UNIT 6 - Caching Implementation <<<--- ###
# It is implemented in unit 3 itself.

### --->>> HOMEWORK UNIT 7 - Wiki <<<--- ###
# The wiki determines student's grade for CS253 course. So to avoid misuse,
# source code of wiki is not included.

# In Unit 3 Homework:
# Entries handler has a ([0-9]+) - where this means anything under
# parentheses will be counted as parameters either for a get or post function.

# In Unit 4 Homework:
# please note use Register Handler not SignupHandler, if you
# use SignUpHandler then it will stop at NotImplementedError

# In Unit 5 Homework:
# parentheses will be counted as parameters either for a get or post function.
# (?:.json)? - It means optionally match to .json after the url.

app = webapp2.WSGIApplication([
                            ('/unit1', Unit1),
                            ('/unit2/birthday', Birthday),
                            ('/unit2/thanks', Thanks),
                            ('/unit2/rot13', RotFunction),
                            ('/unit2/signup', SignUp),
                            ('/unit2/welcome', Welcome),
                            ('/unit2/shoppinglist', Shopping),
                            ('/unit2/fizzbuzz/', FizzBuzz),
                            ('/unit3/ascii', AsciiArt),
                            ('/unit3/blog/newpost', NewPost),
                            ('/unit3/blog/([0-9]+)(?:\.json)?', PermaLink),
                            ('/unit3/blog/?(?:\.json)?', Front),
                            ('/unit3/blog/flush', FlushHandler),
                            ('/unit4/visits', Visits),
                            ('/unit4/signup', Register),
                            ('/unit4/welcome', Unit4Welcome),
                            ('/unit4/login', Login),
                            ('/unit4/logout', Logout),
                            ('/home', HomePage)], debug=True)

def main():
    run_wsgi_app(app)

if __name__ == "__main__":
    main()


