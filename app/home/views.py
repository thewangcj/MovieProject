# -*- coding: utf-8 -*-
from . import home
from flask import render_template, redirect, url_for, flash, session, request, Response
from app.home.forms import RegisterForm, LoginForm, UserForm, PwdForm, CommentForm
from app.models import User, UserLog, Preview, MovieCollect, Comment, Tag, Movie
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import uuid, os, datetime
from app import db, app, rd
from functools import wraps


def user_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def change_filename(file_name):
    file_info = os.path.splitext(file_name)
    file_name = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) \
                + file_info[1]
    return file_name


@home.route("/<int:page>/", methods=["GET"])
def index(page=None):
    tags = Tag.query.all()
    page_data = Movie.query

    tag_id = request.args.get('tag_id', 0)
    if int(tag_id) != 0:
        page_data = page_data.filter_by(tag_id=int(tag_id))

    star = request.args.get('star', 0)
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))

    time = request.args.get('time', 0)
    if int(time) != 0:
        if int(time) == 1:
            page_data = page_data.order_by(Movie.add_time.desc())
        else:
            page_data = page_data.order_by(Movie.add_time.asc())

    play_num = request.args.get('play_num', 0)
    if int(play_num) != 0:
        if int(play_num) == 1:
            page_data = page_data.order_by(Movie.play_num.desc())
        else:
            page_data = page_data.order_by(Movie.play_num.asc())

    comments_num = request.args.get('comments_num', 0)
    if int(comments_num) != 0:
        if int(comments_num) == 1:
            page_data = page_data.order_by(Movie.comment_num.desc())
        else:
            page_data = page_data.order_by(Movie.comment_num.asc())

    if page is None:
        page = 1
    page_data = page_data.paginate(page=page, per_page=5)

    p = dict(
        tag_id=tag_id,
        star=star,
        time=time,
        play_num=play_num,
        comments_num=comments_num
    )
    return render_template("home/index.html", tags=tags, p=p, page_data=page_data)


@home.route("/login/", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        data = login_form.data
        user = User.query.filter_by(name=data['account']).first()

        if not user:
            flash("此用户不存在！", "err")
            return redirect(url_for('home.login'))

        if not user.check_pwd(data['pwd']):
            flash("密码错误！", "err")
            return redirect(url_for('home.login'))

        session['user'] = data['account']
        session['user_id'] = user.id

        user_log = UserLog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(user_log)
        db.session.commit()
        flash("登录成功！", "ok")
        return redirect(url_for('home.user'))
    return render_template("home/login.html", login_form=login_form)


@home.route("/logout/")
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for("home.login"))


@home.route("/register/", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        data = register_form.data
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex,
            face="default.png"
        )
        db.session.add(user)
        db.session.commit()
        flash("注册成功！", "ok")
    return render_template("home/register.html", register_form=register_form)


@home.route("/user/", methods=["GET", "POST"])
@user_login_req
def user():
    user_form = UserForm()
    user = User.query.get_or_404(session['user_id'])
    user_form.face.validators = []
    if request.method == "GET":
        user_form.name.data = user.name
        user_form.email.data = user.email
        user_form.phone.data = user.phone
        user_form.info.data = user.info

    if user_form.validate_on_submit():
        data = user_form.data

        face_file = secure_filename(user_form.face.data.filename)

        if not os.path.exists(app.config["USER_DIR"]):
            os.makedirs(app.config["USER_DIR"])
            os.chmod(app.config["USER_DIR"], "rw")

        user.face = change_filename(face_file)
        user_form.face.data.save(app.config["USER_DIR"] + user.face)

        name_count = User.query.filter_by(name=data['name']).count()
        if data['name'] != user.name and name_count == 1:
            flash("昵称重复！", "err")
        user.name = data['name']

        email_count = User.query.filter_by(email=data['email']).count()
        if data['email'] != user.email and email_count == 1:
            flash("邮箱重复！", "err")
        user.email = data['email']

        phone_count = User.query.filter_by(phone=data['phone']).count()
        if data['phone'] != user.phone and phone_count == 1:
            flash("手机号重复！", "err")
        user.phone = data['phone']

        user.info = data['info']

        db.session.add(user)
        db.session.commit()
        flash("修改成功！", "ok")
        return redirect(url_for('home.user'))
    return render_template("home/user.html", user_form=user_form, user=user)


@home.route("/pwd/", methods=["GET", "POST"])
@user_login_req
def pwd():
    pwd_form = PwdForm()
    if pwd_form.validate_on_submit():
        data = pwd_form.data
        user = User.query.filter_by(name=session['user']).first()
        if not user.check_pwd(data['old_pwd']):
            flash("旧密码错误！", "err")
            return redirect(url_for("home.pwd"))
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash("修改密码成功！", "ok")
        redirect(url_for("home.logout"))
    return render_template("home/pwd.html", pwd_form=pwd_form)


@home.route("/comments/<int:page>")
@user_login_req
def comments(page):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        User
    ).filter(
        User.id == session['user_id']
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("home/comments.html", page_data=page_data)


@home.route("/login_log/<int:page>", methods=["GET"])
@user_login_req
def login_log(page=None):
    if page is None:
        page = 1
    page_data = UserLog.query.filter_by(
        user_id=int(session['user_id'])
    ).order_by(
        UserLog.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("home/login_log.html", page_data=page_data)


@home.route("/movie_collect/add/", methods=["GET"])
@user_login_req
def movie_collect_add():
    movie_id = request.args.get('movie_id', '')
    user_id = request.args.get('user_id', '')
    movie_collect_count = MovieCollect.query.filter_by(
        user_id=int(user_id),
        movie_id=int(movie_id)
    ).count()
    if movie_collect_count == 1:
        data = dict(ok=0)
    if movie_collect_count == 0:
        movie_collect = MovieCollect(
            user_id=user_id,
            movie_id=movie_id
        )
        db.session.add(movie_collect)
        db.session.commit()
        data = dict(ok=1)
    import json
    return json.dumps(data)


@home.route("/movie_collect/list/<int:page>", methods=["GET"])
@user_login_req
def movie_collect_list(page):
    if page is None:
        page = 1
    page_data = MovieCollect.query.filter(
        MovieCollect.id == session['user_id']
    ).order_by(
        MovieCollect.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("home/movie_collect.html", page_data=page_data)


# 首页上映预告轮播图
@home.route("/animation/", methods=["GET"])
def animation():
    preview_list = Preview.query.all()

    return render_template("home/animation.html", preview_list=preview_list)


@home.route("/search/<int:page>/")
def search(page):
    search_key = request.args.get("search_key", "")
    if page is None:
        page = 1
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + search_key + '%')
    ).order_by(
        Movie.add_time.desc()
    ).paginate(page=page, per_page=5)

    movie_count = Movie.query.filter(
        Movie.title.ilike('%' + search_key + '%')
    ).count()
    page_data.key = search_key
    return render_template("home/search.html", search_key=search_key, page_data=page_data, movie_count=movie_count)


@home.route("/play/<int:id>/<int:page>/", methods=["GET", "POST"])
def play(id=None, page=None):
    if id is None:
        id = 1
    movie = Movie.query.get_or_404(int(id))

    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).filter(
        Movie.id == movie.id
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=5)

    movie.play_num = movie.play_num + 1
    comment_form = CommentForm()
    # if 'user' in session:
    #     print('user')
    if comment_form.validate_on_submit():
        data = comment_form.data
        comment = Comment(
            content=data['content'],
            user_id=session['user_id'],
            movie_id=movie.id
        )
        db.session.add(comment)
        db.session.commit()

        movie.comment_num = movie.comment_num + 1
        db.session.add(movie)
        db.session.commit()
        flash("评论成功", 'ok')
        return redirect(url_for('home.play', id=movie.id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template("home/play.html", movie=movie, comment_form=comment_form, page_data=page_data)


@home.route("/barrage/<int:id>/<int:page>/", methods=["GET", "POST"])
def barrage(id=None, page=None):
    if id is None:
        id = 1
    movie = Movie.query.get_or_404(int(id))

    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).filter(
        Movie.id == movie.id
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=5)

    movie.play_num = movie.play_num + 1
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        data = comment_form.data
        comment = Comment(
            content=data['content'],
            user_id=session['user_id'],
            movie_id=movie.id
        )
        db.session.add(comment)
        db.session.commit()

        movie.comment_num = movie.comment_num + 1
        db.session.add(movie)
        db.session.commit()
        flash("评论成功", 'ok')
        return redirect(url_for('home.barrage', id=movie.id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template("home/barrage.html", movie=movie, comment_form=comment_form, page_data=page_data)


@home.route("/tm/v2/", methods=["GET", "POST"])
def tm():
    import json
    # 获取弹幕消息队列
    if request.method == 'GET':
        id = request.args.get('id')
        key = 'movie' + str(id)
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            res = {
                "code": 1,
                "danmaku": [json.loads(v.decode('utf-8')) for v in msgs]
            }
        else:
            res = {
                "code": 1,
                "danmaku": []
            }
        resp = json.dumps(res)
    # 添加弹幕
    if request.method == 'POST':
        data = json.loads(request.get_data(as_text=True))
        msg = {
            "__v": 0,
            "author": data['author'],
            "time": data['time'],
            'text': data['text'],
            'color': data['color'],
            'type': data['type'],
            'ip': request.remote_addr,
            '_id': datetime.datetime.now().strftime("%y%m%d%H%M%S") + uuid.uuid4().hex,
            'player': [data['player']]
        }
        res = {
            "code": 1,
            "data": msg
        }
        resp = json.dumps(res)
        rd.lpush('movie' + str(data['player']), json.dumps(msg))
    return Response(resp, mimetype='application/json')
