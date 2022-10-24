import os

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateCommentForm, RegisterForm, LoginForm
from flask_gravatar import Gravatar
from secrets import token_hex
from functools import wraps
from flask_debugtoolbar import DebugToolbarExtension
# Run Pydoc window with: python -m pydoc -p <port_number>
# Using heroku, gunicorn. Need to have Procfile in root directory.



Flask.secret_key = token_hex(16)
app = Flask(__name__)
app.config['SECRET_KEY'] = token_hex(32)
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'  # for running local db file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')  # for running postgres on heroku
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True  # THis is for debug toolbar
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# toolbar = DebugToolbarExtension(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password_hash = db.Column(db.String(250), nullable=False)
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')

    def __repr__(self):
       return f'User: {self.name}'


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User. Note this should have been an Int but too late now.
    author_id = db.Column(db.String(250), db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates='parent_post')

    def __repr__(self):
       return f'Post: {self.title}'


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(2500), unique=True, nullable=False)
    parent_post = relationship("BlogPost", back_populates='comments')
    author_id = db.Column(db.String(250), db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates='comments')
    parent_post_id = db.Column(db.String(250), db.ForeignKey('blog_posts.id'))
    # date = db.Column(db.String(250), nullable=False)

    def __repr__(self):
        return f'Comment on: {self.parent_post.title}, by {self.comment_author}'

## HELPER FUNCTIONS
def make_hash(password):  # returns 'method$salt$hash'
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

# This function is required by the login manager.
@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(user_id)
    if user:
        print(f'id: {user.id}, name: {user.name}, email: {user.email} ')
    return user

def is_admin():
    # User with id 1 in database is the admin for the blog
    if current_user.is_authenticated and current_user.id == 1:
        return True
    else:
        return False

# This is a decorator function
def admin_only(func):
    @wraps(func)
    # This line is required so that flask doesn't see the multiple routes assigned to the same function ('wrapper')
    #  See https://stackoverflow.com/questions/17256602/assertionerror-view-function-mapping-is-overwriting-an-existing-endpoint-functi
    def wrapper(*args, **kwargs):
        if not is_admin() or current_user.is_anonymous:
            # flash('403 Not authorized. Please log in as admin')
            # return redirect(url_for('login'), 403)
            abort(403)
        return func(*args, **kwargs)
    return wrapper


def initialize_db():
    db.create_all()
    new_user = User(
        name="Chris",
        email="a@b.c",
        password_hash=make_hash('asdf'),
        posts=[BlogPost(
            title="A Life of Cactus",
            subtitle="Subtitle of cactus",
            date=date.today().strftime("%B %d, %Y"),
            body='blah blah blah...',
            img_url='https://www.gardeningknowhow.com/wp-content/uploads/2021/01/golden-barrel-cactus-1536x1152.jpg'
        )]
    )

    db.session.add(new_user)
    db.session.commit()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    users = User.query.all()
    print(f'Getting posts. First post title: {posts[0].title}, Author id: {posts[0].author_id}')
    return render_template("index.html",
                           all_posts=posts,
                           all_users=users,
                           logged_in=current_user.is_authenticated,
                           is_admin=is_admin()
                           )


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
        # if User.query.filter_by(email=request.form.get('email')).first():
            print(f'Trying to add email: {request.form.get("email")}. Found: {User.query.filter_by(email=request.form.get("email"))}')
            flash('Email already in use. Log in instead')
            return redirect(url_for('login'))
        user = User(
            name=request.form.get('name'),
            email=request.form.get('email').lower(),
            password_hash=make_hash(request.form.get('password'))
            # or name=form.name.data,
            #    email=form.email.data...
        )
        print(user)
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        login_user(user)
        flash('Registered and logged in')
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email').lower()).first()
        print(f'User: {user}')
        if user:
            if check_password_hash(user.password_hash, request.form.get('password')):
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect.')
        else:
            flash('Email not registered')
    return render_template('login.html', form=form, logged_in=current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out")
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(parent_post=requested_post)
    comment_form = CreateCommentForm()
    gravatar = Gravatar(app,
                        size=100,
                        rating='g',
                        default='retro',
                        force_default=False,
                        force_lower=False,
                        use_ssl=False,
                        base_url=None)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment")
            return redirect(url_for('login'))
        comment = Comment(
            comment_author=current_user,
            text=comment_form.body.data,
            parent_post_id=post_id,
            # date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(comment)
        db.session.commit()
        flash("Comment submitted successfully")
    return render_template("post.html",
                           post=requested_post,
                           comments=comments,
                           form=comment_form,
                           is_admin=is_admin(),
                           logged_in=current_user.is_authenticated,
                           gravatar=gravatar
                           )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    print('running edit_post')
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

# initialize_db()
if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5001)

