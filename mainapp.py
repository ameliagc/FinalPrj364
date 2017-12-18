import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand
from flask_mail import Mail, Message
from threading import Thread
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/articles"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['HEROKU_ON'] = os.environ.get('HEROKU')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587 #default
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SUBJECT_PREFIX'] = '[NYTimes Articles App]'
app.config['MAIL_SENDER'] = 'Admin <ameliagc364@gmail.com>'
app.config['ADMIN'] = os.environ.get('ADMIN') or "ameliagc364@gmail.com"
app.config['HEROKU_ON'] = os.environ.get('HEROKU')

# Set up Flask debug and necessary additions to app
manager = Manager(app)
db = SQLAlchemy(app) # For database use
migrate = Migrate(app, db) # For database use/updating
manager.add_command('db', MigrateCommand) # Add migrate command to manager
mail = Mail(app) # For email sending

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

# Shell function
def make_shell_context():
    return dict( app=app, db=db, User=User, FavoriteArticles=FavoriteArticles, Article=Article, Search=Search)
manager.add_command("shell", Shell(make_context=make_shell_context))

# Send email functions
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['MAIL_SUBJECT_PREFIX'] + ' ' + subject,
                  sender=app.config['MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr

# Set up for tables
# Association table between search terms and articles
titles = db.Table('titles',db.Column('search_id',db.Integer, db.ForeignKey('search.id')),db.Column('articles_id',db.Integer, db.ForeignKey('articles.id')))

# Assosciation table between articles and user's favorites collection
user_collection = db.Table('user_collection',db.Column('user_id', db.Integer, db.ForeignKey('articles.id')),db.Column('collection_id',db.Integer, db.ForeignKey('favoriteArticles.id')))

class User(UserMixin, db.Model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(255), unique=True, index=True)
	email = db.Column(db.String(64), unique=True, index=True)
	collection = db.relationship('FavoriteArticles', backref='User')
	password_hash = db.Column(db.String(128))

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	@property
	def is_authenticated(self):
		return True

	@property
	def is_active(self):
		return True

class FavoriteArticles(db.Model):
	__tablename__ = "favoriteArticles"
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(255))
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
	articles = db.relationship('Article', secondary=user_collection,backref=db.backref('favoriteArticles',lazy='dynamic'),lazy='dynamic')

class Article(db.Model):
	__tablename__ = "articles"
	id = db.Column(db.Integer, primary_key=True)
	headline = db.Column(db.String)
	url = db.Column(db.String)

	def __repr__(self):
		return "{} : {}".format(self.headline,self.url)

class Search(db.Model):
	__tablename__ = "search"
	id = db.Column(db.Integer, primary_key=True)
	term = db.Column(db.String(32),unique=True)
	headline = db.relationship('Article',secondary=titles,backref=db.backref('search',lazy='dynamic'),lazy='dynamic')

	def __repr__(self):
		return "{} : {}".format(self.id, self.term)


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

# Form to register new user 
class RegistrationForm(FlaskForm):
	email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
	username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	submit = SubmitField('Register User')

	#Additional checking methods for the form
	def validate_email(self,field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self,field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already taken')

# Login form
class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

# Form to search archive for an article
class ArticleSearchForm(FlaskForm):
	search = StringField("Enter a year and month in the following format: YYYY M (ex. 2017 2 for February 2017).", validators=[Required()])
	submit = SubmitField('Submit')

# Form to choose favorite articles
class SaveFavoriteForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    favorite_articles = SelectMultipleField('Articles to save')
    submit = SubmitField("Save")

# Get or create functions
def get_article_by_id(id):
    a = Article.query.filter_by(id=id).first()
    return a

def get_or_create_search_term(db_session, term, article_list = []):
	searchTerm = db_session.query(Search).filter_by(term=term).first()
	if searchTerm:
		print("Found term")
		return searchTerm
	else:
		print("Added term")
		for a in article_list:
			article = get_or_create_article(db_session, headline=a[0], url=a[1])
		searchTerm = Search(term=term)    
		db_session.add(searchTerm)
		db_session.commit()
		return searchTerm

def get_or_create_article(db_session, headline, url):
	article = db.session.query(Article).filter_by(headline=headline).first()
	if article:
		return article
	else:
		article = Article(headline=headline, url=url)
		db_session.add(article)
		db_session.commit()
		return article

def get_or_create_personal_collection(db_session, name, article_list, current_user):
    savedArticles = db_session.query(FavoriteArticles).filter_by(name=name,user_id=current_user.id).first()
    if savedArticles:
        return savedArticles
    else:
        savedArticles = FavoriteArticles(name=name,user_id=current_user.id,articles=[])
        for a in article_list:
            savedArticles.articles.append(a)
        db_session.add(savedArticles)
        db_session.commit()
        return savedArticles

# Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

## Login routes
@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('index'))
		flash('Invalid username or password.')
	return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,username=form.username.data,password=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in!')
		return redirect(url_for('login'))
	return render_template('register.html',form=form)

# View routes
@app.route('/', methods=['GET', 'POST'])
def index():
    articles = Article.query.all()
    form = ArticleSearchForm()
    if form.validate_on_submit():
        if db.session.query(Search).filter_by(term=form.search.data).first():
            term = db.session.query(Search).filter_by(term=form.search.data).first()
            all_articles = []
            for i in articles:
                all_articles.append((i.headline, i.url))
            return render_template('all_articles.html', all_articles = all_articles)
        else:
        	search_split = form.search.data.split()
        	year = search_split[0]
        	month = search_split[1]
        	baseURL = "https://api.nytimes.com/svc/archive/v1/"+year+"/"+month+".json"
        	params_diction = {}
        	params_diction['api-key'] = "90bc58d558884138ac19ed6e27640df7"
        	response = requests.get(baseURL, params = params_diction)
        	articleResponse = json.loads(response.text)
        	response = articleResponse['response']
        	docs = response['docs']
        	data = docs[0]
        	articleFieldsRequired = []

        	# Check to see if any fields are empty, if so add statement to database instead of null value
        	if data['headline'] == None:
        		headline = "No headline"
        	else:
        		headline = data['headline']['main']

        	if data['web_url'] == None:
        		url = "https://www.nytimes.com/"
        	else:
        		url = data['web_url']

        	articleFieldsRequired.append((headline, url))
        	searchterm = get_or_create_search_term(db.session, form.search.data, articleFieldsRequired)
        	# Set up to send email if new article is searched for
        	if app.config['ADMIN']:
        		send_email(app.config['ADMIN'], 'New Article','mail/new_article', song=form.search.data)
        		flash("Email would be sent to {} if email secure server were set up".format(app.config['ADMIN']))
        	flash('A new article has been successfully added to your list!')
    return render_template('index.html', form=form)

@app.route('/all_articles')
def see_all():
    all_articles = []
    article_all = Article.query.all()
    for a in article_all:
        all_articles.append((a.headline, a.url))
    return render_template('all_articles.html', all_articles=all_articles)

@app.route('/create_article_collection',methods=["GET","POST"])
@login_required
def save_favorites():
    form = SaveFavoriteForm()
    choices = []
    for a in Article.query.all():
        choices.append((a.id, a.headline))
    form.favorite_articles.choices = choices
    if request.method == 'POST':
        articles_selected = form.favorite_articles.data
        article_objects = [get_article_by_id(int(id)) for id in articles_selected]
        get_or_create_personal_collection(db.session,current_user=current_user,name=form.name.data,article_list=article_objects)
        return "Favorites saved"
    return render_template('save_articles.html',form=form)

@app.route('/see_collection', methods=["GET", "POST"])
@login_required
def seeFavArticles():
	collection = FavoriteArticles.query.all()
	fav_articles = []
	for a in FavoriteArticles.query.all():
		for name in a.articles:
			fav_articles.append((a.name, name.headline))
	print(fav_articles)
	return render_template('view_favorites.html', fav_articles=fav_articles)

if __name__ == '__main__':
	db.create_all()
	manager.run()