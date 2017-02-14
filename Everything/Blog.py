# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import jinja2
import webapp2
import re 
import hashlib
import hmac
from string import letters
import random 

from google.appengine.ext import db 


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment ( loader = jinja2.FileSystemLoader(template_dir))

secret = "asasdjklfsiuhewjblhasdfy38"

def make_pw_hash(name,pw,salt=None):
	if not salt:
		salt = make_salt()
		h = hashlib.sha256(name+pw+salt).hexdigest()
		return '%s,%s'% (salt,h)


def render_str(self, template, **params):
		t=jinja_env.get_template(template)
		return t.render(params)

def make_secure_val(val):
	return '%s|%s' %(val,hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def make_salt(length=5):
	return ''.join(random.choice(letters) for x in range(length))
	

def valid_pw(name,password,h):
	salt = h.split(',')[0]
	return h == make_pw_hash (name,password,self)

def users_key(group ='default'):
	return db.Key.from_path('users',group)


class Handler(webapp2.RequestHandler):
	def write (self, *a , **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t=jinja_env.get_template(template)
		return t.render(params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('set-cookie', '%s|%s;path=/' %(name,cookie_val))

	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self,user):
		self.set_secure_cookie('user_id',str(user.key().id()))

	def logout (self):
		self.response.headers.add_header('set-cookie', 'user_id=; path =/')

	def initialize (self, *a , **kw):
		webapp2.RequestHandler.initialize(self, *a ,**kw)
		uid = self.read_secure_cookie ('user_id')
		self.user = uid and User.by_id(int(uid))



class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty ()

	@classmethod
	def by_id(cls,uid):
		return user.get_by_id(uid,parent = users_key())

	@classmethod
	def by_name(cls,name):
		u = User.all().filter('name=',name).get()
		return u 

	@classmethod
	def login2 (cls,name,pw):
		u = cls.by_name(name)
		if u and valid_pw(name,pw,u.pw_hash):
			return u 

	@classmethod
	def register (cls,name,pw,email = None):
		pw_hash = make_pw_hash(name,pw)
		return User(parent=users_key(), name = name , pw_hash = pw_hash, email = email)



class blog(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty( required = True)
	created = db.DateTimeProperty(auto_now_add = True)

USER_RE = re.compile (r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)
PASS_RE =re.compile(r"^.{3,20}$")
def valid_password (password):
	return password and PASS_RE.match(password)
EMAIL_RE = re.compile (r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return  not email or EMAIL_RE.match(email) 


#class for the main signup and insuring user info is valid  
class Signup(Handler):
	def get(self):
		self.render("index.html")


	def post(self):
		have_error = False 
		self.username =self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username , email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That seems to be an invalid username."
			have_error = True

		if not valid_password(self.password):
			params ['error_password'] = "That is not a valid password "
			have_error = True

		elif self.password != self.verify:
			params['error_verify'] = "The passwords did not match!"
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That is not a valid email"
			have_error = True 

		if have_error == True:
			self.render('index.html',**params)
		else: 
			self.done()


	def done(self):
		u = User.by_name(self.username)
		if u :
			msg = 'Username has already been taken'
			self.render('index.html', error_username = msg)
		else:
			u = User.register(self.username,self.password,self.email)
			u.put()

			self.login(u)
			self.redirect('/welcome')


# class Register(Signup):
# 	def done(self):
# 		self.write('f')
		# u = User.by_name(self.username)
		# self.render('index.html',error_username = 'kjhdlasfl')
		# if u :
		# 	msg = 'Username has already been taken'
		# 	self.render('index.html', error_username = msg)
		# else:
		# 	u = User.register(self.username,self.password,self.email)
		# 	u.put()
		# 	self.login(u)
		# 	self.redirect('/welcome')



class Login(Handler):
	def get(self):
		self.render('login.html')

	def post (self):
		username= self.request.get('username')
		password = self.request.get('password')

		u = User.login2(username,password)
		if u:
			self.login(u)
			self.redirect('/welcome')
		else:
			msg = 'invalid login'
			self.render('login.html', error = msg)

class welcome(Handler):
	def get(self):
		if self.user:
			self.render('mainpage.html' , username = self.user.name)
		else:
		 	self.redirect('/signup')

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/signup')






#class to display the new post page 
class Newpost(Handler):
	def get(self):
		self.render('newpost.html') 

	def post (self):
		title = self.request.get('title')
		content = self.request.get('content')
		if title and content:
			Blog=blog(title =title, content = content)
			key= Blog.put()
			self.redirect("/blog/%d" %key.id())
		else:
			self.render("newpost.html")
		###create blog class
class blog_single(Handler):
	def get(self, blog_id):
        	Blog = blog.get_by_id(int(blog_id))
        	self.render("blog.html", Blogs = [Blog])
	
#class to display the main page 
class Mainpage(Handler):
	def get(self):
		# username = self.request.get('username')
		# if valid_username(username):
		# 	Blogs = db.GqlQuery("SELECT * FROM blog ""ORDER BY created DESC ")
		# 	self.render("mainpage.html",Blogs = Blogs ,  username = username  )
		# else:
		# 	self.redirect('/signup')


		
		

app = webapp2.WSGIApplication([('/mainpage', Mainpage) , ('/newpost',Newpost),('/blog/(\d+)', blog_single), ("/login", Login), ('/signup', Signup), ('/login',Login), ('/logout',Logout), ('/welcome',welcome)], debug=True)



