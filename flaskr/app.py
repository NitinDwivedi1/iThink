from flask import Flask, render_template,request,redirect,url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import PasswordField, validators, StringField, SelectField, TextAreaField, SubmitField, widgets
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo
from wtforms.fields.html5 import DateField
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.sql.expression import update
from sqlalchemy.sql import func
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import pytz

file_path = os.path.abspath(os.getcwd())+"\database.db"
IST = pytz.timezone('Asia/Kolkata')

app = Flask(__name__)
app.secret_key=os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI']= "sqlite:///"+file_path
engine=create_engine("sqlite:///"+file_path)
Bootstrap(app)
db=SQLAlchemy(app)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

class User(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    fullname=db.Column(db.String(20))
    email=db.Column(db.String(50), unique=True)
    dob=db.Column(db.Integer)
    profession=db.Column(db.String(20))
    username=db.Column(db.String(20), unique=True)
    password=db.Column(db.String(80))

class PostData(UserMixin, db.Model):
    p_id=db.Column(db.Integer, primary_key=True)
    PostCategory=db.Column(db.String(15))
    title=db.Column(db.String(20))
    content=db.Column(db.Text)
    timestamp = db.Column(db.DateTime(timezone=True), default=func.now(IST))
    id=db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PostComment(UserMixin, db.Model):
    c_id=db.Column(db.Integer, primary_key=True)
    comment=db.Column(db.Text)
    timestamp=db.Column(db.DateTime(timezone=True), default=func.now(IST))
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    p_id = db.Column(db.Integer, db.ForeignKey('post_data.p_id'), nullable=False)

class Notification(UserMixin, db.Model):
    n_id=db.Column(db.Integer, primary_key=True)
    commentator=db.Column(db.Integer,nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=func.now(IST))
    p_id=db.Column(db.Integer, db.ForeignKey('post_data.p_id'),nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    fullname = StringField('Full name', validators=[InputRequired(), Length(min=3, max=20, message='Field must be between 3 and 20 characters long.')])
    email = StringField('Email id', validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
    dob = DateField('Date of birth',format="%Y-%m-%d", validators=[InputRequired()])
    profession = StringField('Profession', validators=[InputRequired(), Length(min=2, max=20, message='Field must be between 2 and 20 characters long.')])
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=20, message='Field must be between 3 and 20 characters long.')])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80, message='Field must be between 8 and 80 characters long.')])
    confirmPassword = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords didn\'t match!')])

class UpdateForm(FlaskForm):
    fullname = StringField('Full name', validators=[InputRequired(), Length(min=3, max=20, message='Field must be between 3 and 20 characters long.')])
    email = StringField('Email id', validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
    dob = DateField('Date of birth',format="%Y-%m-%d", validators=[InputRequired()])
    profession = StringField('Profession', validators=[InputRequired(), Length(min=2, max=20, message='Field must be between 2 and 20 characters long.')])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class PostForm(FlaskForm):
    categories=["Technology", "Sports","Entertainment" , "Knowledge", "Lifestyle", "Fashion", "Cooking", "Politics"]
    PostCategory = SelectField('Category', choices=categories, validators=[InputRequired()])
    title = StringField('Title', validators=[InputRequired()])
    content = TextAreaField('Content', validators=[InputRequired()])

class CommentForm(FlaskForm):
    comment = StringField("Comment", validators=[InputRequired()])

@app.route('/', methods=['GET','POST'])
@app.route('/<pid>', methods=['GET','POST'])
@login_required
def index(pid=None):
    result=db.session.execute('select p.PostCategory, p.title, p.content, p.timestamp, u.username, p.p_id from user u, post_data p where u.id=p.id order by timestamp desc')
    posts=[list(row) for row in result]
    form=None
    cmnts=None

    if pid != None:
        ucmnts=db.session.execute('select c.comment, c.timestamp, u.username, p.p_id from post_comment c, user u, post_data p where c.p_id=p.p_id and u.id=c.id')
        cmnts=[list(row) for row in ucmnts]
        form =CommentForm()
        if form.validate_on_submit():
            postComment=PostComment(comment=form.comment.data,timestamp=func.now(IST),id=current_user.id,p_id=pid)
            db.session.add(postComment)
            db.session.commit()
            notification=Notification(commentator=current_user.id,timestamp=func.now(IST),p_id=pid)
            db.session.add(notification)
            db.session.commit()
            flash('Comment posted!',category='success')
            return redirect(url_for('index'))
    return render_template("index.html",posts=posts, form=form, cmnts=cmnts,page='index',pid=pid)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user=User(fullname=form.fullname.data,
                      email=form.email.data,
                      dob=form.dob.data,
                      profession=form.profession.data,
                      username=form.username.data,
                      password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("You have been registered successfully!", category='success')
        return redirect(url_for("index"))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("index"))
        flash("Invalid username or password!", category='error')
        return redirect(url_for('login'))

    return render_template("login.html", form=form)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    fullname = current_user.fullname
    email = current_user.email
    dob = current_user.dob
    profession = current_user.profession
    username = current_user.username

    result = db.session.execute('select PostCategory, title, content, p_id ,timestamp from post_data  where id=:val order by timestamp desc', {'val':current_user.id})
    posts = [list(row) for row in result]
    return render_template('profile.html',fullname=fullname,
                                          email=email,
                                          dob=dob,
                                          profession=profession,
                                          username=username,
                                          posts=posts,page='profile')
@app.route('/post', methods=['GET','POST'])
@login_required
def post():
    form = PostForm()
    if form.validate_on_submit():
        postData=PostData(PostCategory=form.PostCategory.data,
                          title=form.title.data,
                          content=form.content.data,
                          id=current_user.id,
                          timestamp=func.now(IST))
        db.session.add(postData)
        db.session.commit()
        flash("Posted!", category='success')
        return redirect(url_for('index'))
    return render_template('post.html',form=form,page='post')

@app.route('/edit',methods=['GET','POST'])
def editInfo():
    form=UpdateForm()
    if form.validate_on_submit():
        conn = engine.connect()
        stmt= update(User).values(email=(form.email.data)).where(User.id==current_user.id)
        conn.execute(stmt)

        db.session.commit()
        flash("Profile updated!", category='success')
        return redirect(url_for('profile'))
    return render_template('update.html',form=form)

@app.route('/delete/<did>',methods=['GET','POST'])
@login_required
def deletePost(did):
    db.session.execute('delete from post_data where p_id=:val',{'val':did})
    db.session.commit()
    flash("Post deleted!", category='success')
    return redirect(url_for('profile'))

@app.route('/notification', methods=['GET','POST'])
@login_required
def notification():
    notifications=db.session.execute('select u.username, n.p_id, n.timestamp from user u, notification n where u.id=n.commentator order by timestamp desc')
    notifications = [list(row) for row in notifications]
    userPosts = db.session.execute('select p_id from post_data where post_data.id=:val',{'val':current_user.id})
    userPosts = [list(row) for row in userPosts]
    return render_template('notification.html',notifications=notifications, userPosts=userPosts,page='notification')