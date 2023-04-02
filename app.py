from flask import Flask, render_template,request,redirect,url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import PasswordField, validators, StringField, SelectField, TextAreaField, SubmitField, widgets
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo
from wtforms.fields import DateField
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.sql.expression import update
from sqlalchemy.sql import func
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY']=os.urandom(16)

app.config['MYSQL_HOST'] = os.environ.get("MYSQL_HOST")
app.config['MYSQL_USER'] = os.environ.get("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.environ.get("MYSQL_PASS")
app.config['MYSQL_DB'] = os.environ.get("MYSQL_DB")
mysql = MySQL(app)


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
@app.route('/hide_cmnts/<cpid>', methods=['GET','POST'])
def index(pid=None,cpid=None):
    if 'logged in' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('select p.post_category, p.title, p.content, p.timestamp, u.username, p.p_id from accounts u, post_data p where u.id=p.id order by timestamp desc')
        result = cursor.fetchall()
        print(result)
        posts=[row for row in result]
        form=None
        cmnts=None

        if pid != None:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('select c.comment, c.timestamp, u.username, p.p_id from post_comment c, accounts u, post_data p where c.p_id=p.p_id and u.id=c.id ')
            ucmnts=cursor.fetchall()
            print(ucmnts)
            cmnts=[row for row in ucmnts]
            form =CommentForm()
            if form.validate_on_submit():
                time=datetime.now()
                comment = form.comment.data
                timestamp = time
                id = session['id']
                p_id = pid
                cursor.execute('INSERT INTO ithink_db.post_comment VALUES (NULL, %s, %s, %s, %s)',(comment, timestamp, id, p_id))
                mysql.connection.commit()

                commentator = session['id']
                timestamp = time
                p_id = pid
                cursor.execute('INSERT INTO ithink_db.notification VALUES (NULL, %s, %s, %s)',
                               (commentator, timestamp, p_id,))
                mysql.connection.commit()
                flash("Comment posted!",category='success')
                return redirect(url_for('index'))
        return render_template("index.html",posts=posts, form=form, cmnts=cmnts,page='index',pid=pid)
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=''
    form = RegisterForm()
    # if form.validate_on_submit():
    if request.method=='POST':
        hashed_password = generate_password_hash(form.password.data)
        fullname = form.fullname.data,
        email = form.email.data,
        dob = form.dob.data,
        profession = form.profession.data,
        username = form.username.data,
        password = hashed_password

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username,))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', str(email)):
            msg = 'Invalid email address !'
        # elif not re.match(r'[A-Za-z0-9]+', str(fullname)):
        #     msg = 'name must contain only characters and numbers !'
        else:
            print("else")
            cursor.execute('INSERT INTO ithink_db.accounts VALUES (NULL, % s, % s, % s, % s, % s, % s)',
                           (username, password, email, fullname, dob, profession,))
            mysql.connection.commit()
            print("hello")
            msg = 'You have successfully registered !'
            flash("You have been registered successfully!", category='success')
            print(msg)
            print("hiiiii")
            return redirect(url_for("login"))
        print(msg)
        flash(msg, category='error')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=''
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        print(username, password)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username,))
        account = cursor.fetchone()
        print(account)
        if account:
            if check_password_hash(account['password'], password):
                session['logged in'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                msg = 'Logged in successfully !'
                flash(msg, category='success')
                return redirect(url_for('index'))
            else:
                print("wrong password")
                msg = 'Incorrect Password'
        else:
            print("wrong username")
            msg="Account doesn't exist"
        flash(msg, category='error')
        return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    if 'logged in' in session:
        session.pop('logged in', None)
        session.pop('id', None)
        session.pop('username', None)
        # Redirect to login page
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'logged in' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('select fullname, email, dob, profession, username from accounts where id=%s', [session['id']])
        user = cursor.fetchone()
        print(user)
        fullname = user['fullname']
        email = user['email']
        dob = user['dob']
        profession = user['profession']
        username = user['username']

        cursor.execute('select post_category, title, content, p_id ,timestamp from post_data  where id=%s order by timestamp desc', [session['id']])
        result = cursor.fetchall()
        posts = [row for row in result]
        return render_template('profile.html',fullname=fullname,
                                              email=email,
                                              dob=dob,
                                              profession=profession,
                                              username=username,
                                              posts=posts,page='profile')
    else:
        return redirect(url_for('login'))


@app.route('/post', methods=['GET','POST'])
def post():
    if 'logged in' in session:
        form = PostForm()
        if form.validate_on_submit():
            PostCategory = form.PostCategory.data
            title = form.title.data
            content = form.content.data
            id = session['id']
            timestamp = datetime.now()

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO ithink_db.post_data VALUES(NULL, %s, %s, %s, %s, %s)', (PostCategory, title, content, timestamp, id))
            mysql.connection.commit()
            flash('Posted!', category='success')
            return redirect(url_for('index'))
        return render_template('post.html',form=form,page='post')
    else:
        return redirect(url_for('login'))


@app.route('/edit',methods=['GET','POST'])
def editInfo():
    if 'logged in' in session:
        form=UpdateForm()
        if form.validate_on_submit():
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('update ithink_db.accounts set fullname=%s, email=%s, dob=%s, profession=%s where id=%s', (form.fullname.data, form.email.data, form.dob.data, form.profession.data, session['id']))
            mysql.connection.commit()
            flash("Profile updated!", category='success')
            return redirect(url_for('profile'))
        return render_template('update.html',form=form)
    else:
        return redirect(url_for('login'))


@app.route('/delete/<did>',methods=['GET','POST'])
def deletePost(did):
    if 'logged in' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('delete from ithink_db.post_data where p_id=%s',(did))
        mysql.connection.commit()
        flash("Post deleted!", category='success')
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('login'))


@app.route('/notification', methods=['GET','POST'])
def notification():
    if 'logged in' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('select u.username, n.p_id, n.timestamp from accounts u, notification n where u.id=n.commentator order by timestamp desc')
        notifications = cursor.fetchall()
        print(notifications)
        notifications = [row for row in notifications]
        cursor.execute('select p_id from post_data where post_data.id=%s', [session['id']])
        userPosts = cursor.fetchall()
        print(userPosts)
        userPosts = [row for row in userPosts]
        return render_template('notification.html',notifications=notifications, userPosts=userPosts,page='notification')
    else:
        return redirect(url_for('login'))