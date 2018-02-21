# -*- coding: utf-8 -*-
from app import db, app
from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.models import Admin, Tag, Movie, Preview, User, Comment, MovieCollect, OptionLog, AdminLog, UserLog, Auth, Role
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from functools import wraps
from werkzeug.utils import secure_filename
import os, uuid, datetime


# 上下文处理器
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session['admin_id']
        ).first()
        auths = admin.role.auth
        auths = list(map(lambda v: int(v), auths.split(',')))
        auth_list = Auth.query.all()
        urls = [auth.url for auth in auth_list for auth_id in auths if auth.id == auth_id]
        rule = request.url_rule
        print(urls)
        print(rule)
        if str(rule) not in urls:
            abort(404)
        return f(*args, **kwargs)

    return decorated_function


# 修改文件名称
def change_filename(file_name):
    file_info = os.path.splitext(file_name)
    file_name = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) \
                + file_info[1]
    return file_name


@admin.route("/")
@admin_login_req
@admin_auth
def index():
    return render_template("admin/index.html")


@admin.route("/login/", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        data = login_form.data
        admin = Admin.query.filter_by(name=data["account"]).first()
        if not admin.check_pwd(data["pwd"]):
            flash("密码错误", "err")
            return redirect(url_for("admin.login"))
        session["admin"] = data["account"]
        session['admin_id'] = admin.id

        admin_log = AdminLog(
            admin_id=admin.id,
            ip=request.remote_addr,
        )
        db.session.add(admin_log)
        db.session.commit()

        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template("admin/login.html", login_form=login_form)


@admin.route("/logout/")
@admin_login_req
def logout():
    session.pop("admin", None)
    session.pop("admin_id", None)
    return redirect(url_for("admin.login"))


# 修改密码
@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_req
def pwd():
    pwd_form = PwdForm()
    if pwd_form.validate_on_submit():
        data = pwd_form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功！", "ok")
        redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html", pwd_form=pwd_form)


@admin.route("/tag/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_add():
    tag_form = TagForm()
    if tag_form.validate_on_submit():
        data = tag_form.data
        tag = Tag.query.filter_by(name=data["name"]).count()
        if tag == 1:
            flash("名称已经存在！", "err")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(
            name=data["name"]
        )
        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功！", "ok")
        option_log = OptionLog(
            admin_id=session["admin_id"],
            ip=request.remote_addr,
            reason="添加%s标签" % data['name'],
        )
        db.session.add(option_log)
        db.session.commit()
        redirect(url_for("admin.tag_add"))
    return render_template("admin/tag_add.html", form=tag_form)


@admin.route("/tag/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/tag_list.html", page_data=page_data)


@admin.route("/tag/del/<int:id>/")
@admin_login_req
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功！", "ok")
    return redirect(url_for("admin.tag_list", page=1))


@admin.route("/tag/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    tag_form = TagForm()
    tag = Tag.query.get_or_404(id)
    if tag_form.validate_on_submit():
        data = tag_form.data
        tag_count = Tag.query.filter_by(name=data["name"]).count()
        if tag.name != data["name"] and tag_count == 1:
            flash("名称已经存在！", "err")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data["name"]
        db.session.add(tag)
        db.session.commit()
        flash("修改标签成功！", "ok")
        redirect(url_for("admin.tag_edit", id=id))
    return render_template("admin/tag_edit.html", form=tag_form, tag=tag)


@admin.route("/movie/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_add():
    movie_form = MovieForm()
    if movie_form.validate_on_submit():
        data = movie_form.data
        movie_file = secure_filename(movie_form.url.data.filename)
        movie_logo = secure_filename(movie_form.logo.data.filename)

        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")

        url = change_filename(movie_file)
        logo = change_filename(movie_logo)
        movie_form.url.data.save(app.config["UP_DIR"] + url)
        movie_form.logo.data.save(app.config["UP_DIR"] + logo)

        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            play_num=0,
            comment_num=0,
            tag_id=int(data["tag_id"]),
            area=data["area"],
            release_time=data["release_time"],
            length=data["length"]
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功！", "ok")
        return redirect(url_for("admin.movie_add"))
    return render_template("admin/movie_add.html", movie_form=movie_form)


@admin.route("/movie/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/movie_list.html", page_data=page_data)


@admin.route("/movie/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def movie_del(id=None):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash("删除电影成功！", "ok")
    return redirect(url_for("admin.movie_list", page=1))


@admin.route("/movie/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    movie_form = MovieForm()
    # 视频和海报可以不修改，所以可以为空，将 validators 设置为空
    movie_form.url.validators = []
    movie_form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))

    if request.method == "GET":
        movie_form.info.data = movie.info
        movie_form.tag_id.data = movie.tag_id
        movie_form.star.data = movie.star
        # print(movie_form.url.data)

    if movie_form.validate_on_submit():
        data = movie_form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count
        if movie_count == 1 and movie.title != data["title"]:
            flash("电影名称重复！", "err")
            return redirect(url_for("admin.movie_edit", id=movie.id))

        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")

        # 如果修改了电影文件
        # print(movie_form.url.data)
        if movie_form.url.data != "":
            movie_file = secure_filename(movie_form.url.data.filename)
            movie.url = change_filename(movie_file)
            movie_form.url.data.save(app.config["UP_DIR"] + movie.url)
        # 如果修改了电影海报
        if movie_form.logo.data != "":
            movie_logo = secure_filename(movie_form.logo.data.filename)
            movie.logo = change_filename(movie_logo)
            movie_form.logo.data.save(app.config["UP_DIR"] + movie.logo)

        movie.star = data["star"]
        movie.tag_id = data["tag_id"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]
        movie.info = data["info"]
        movie.title = data["title"]

        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功！", "ok")
        return redirect(url_for("admin.movie_edit", id=movie.id))
    return render_template("admin/movie_edit.html", movie_form=movie_form, movie=movie)


@admin.route("/preview/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_add():
    preview_form = PreviewForm()
    if preview_form.validate_on_submit():
        data = preview_form.data
        preview_logo = secure_filename(preview_form.logo.data.filename)

        if not os.path.exists(app.config["UP_DIR"]):
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], "rw")

        logo = change_filename(preview_logo)
        preview_form.logo.data.save(app.config["UP_DIR"] + logo)

        preview = Preview(
            title=data["title"],
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash("上传预告成功", "ok")
        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", preview_form=preview_form)


@admin.route("/preview/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(
        Preview.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/preview_list.html", page_data=page_data)


@admin.route("/preview/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()
    flash("删除预告成功！", "ok")
    return redirect(url_for("admin.preview_list", page=1))


@admin.route("/preview/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_edit(id=None):
    preview_form = PreviewForm()
    preview_form.logo.validators = []

    preview = Preview.query.get_or_404(int(id))

    if request.method == "GET":
        preview_form.title.data = preview.title

    if preview_form.validate_on_submit():
        data = preview_form.data

        preview_count = Preview.query.filter_by(title=data["title"]).count
        if preview_count == 1 and preview.title != data["title"]:
            flash("预告名称重复！", "err")
            return redirect(url_for("admin.movie_edit", id=preview.id))

        preview.title = data["title"]

        if preview_form.logo.data != "":
            preview_logo = secure_filename(preview_form.logo.data.filename)
            preview.logo = change_filename(preview_logo)
            preview_form.logo.data.save(app.config["UP_DIR"] + preview.logo)

        db.session.add(preview)
        db.session.commit()
        flash("修改预告成功", "ok")
        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", preview_form=preview_form, preview=preview)


@admin.route("/user/view/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


@admin.route("/user/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(
        User.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/user_list.html", page_data=page_data)


@admin.route("/user/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除会员成功！", "ok")
    return redirect(url_for('admin.user_list', page=1))


@admin.route("/comment/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def comment_list(page):
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/comment_list.html", page_data=page_data)


@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除会员成功！", "ok")
    return redirect(url_for('admin.comment_list', page=1))


@admin.route("/movie_collect/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def movie_collect_list(page):
    if page is None:
        page = 1
    page_data = MovieCollect.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == MovieCollect.movie_id,
        User.id == MovieCollect.user_id
    ).order_by(
        MovieCollect.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/movie_collect_list.html", page_data=page_data)


@admin.route("/movie_collect/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def movie_collect_del(id=None):
    movie_collect = MovieCollect.query.get_or_404(int(id))
    db.session.delete(movie_collect)
    db.session.commit()
    flash("删除会员成功！", "ok")
    return redirect(url_for('admin.movie_collect_list', page=1))


@admin.route("/option_log/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def option_log_list(page=None):
    if page is None:
        page = 1
    page_data = OptionLog.query.join(
        Admin
    ).filter(
        Admin.id == OptionLog.admin_id
    ).order_by(
        OptionLog.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/option_log.html", page_data=page_data)


@admin.route("/admin_log/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def admin_log_list(page=None):
    if page is None:
        page = 1
    page_data = AdminLog.query.join(
        Admin
    ).filter(
        Admin.id == AdminLog.admin_id
    ).order_by(
        AdminLog.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/admin_log.html", page_data=page_data)


@admin.route("/user_log/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def user_log_list(page=None):
    if page is None:
        page = 1
    page_data = UserLog.query.join(
        User
    ).filter(
        User.id == UserLog.user_id
    ).order_by(
        UserLog.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/user_log.html", page_data=page_data)


@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    role_form = RoleForm()
    if role_form.validate_on_submit():
        data = role_form.data
        role = Role(
            name=data['name'],
            auth=",".join(map(lambda v: str(v), data['auth']))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
    return render_template("admin/role_add.html", role_form=role_form)


@admin.route("/role/list/<int:page>", methods=["GET"])
@admin_login_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(
        Role.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/role_list.html", page_data=page_data)


@admin.route("/role/del/<int:id>", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_del(id=None):
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！", "ok")
    return redirect(url_for("admin.role_list", page=1))


@admin.route("/role/edit/<int:id>", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_edit(id=None):
    role_form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method == "GET":
        role_form.auth.data = list(map(lambda v: int(v), role.auth.split(",")))

    if role_form.validate_on_submit():
        data = role_form.data
        role.name = data['name']
        role.auth = ",".join(map(lambda v: str(v), data['auth']))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！", "ok")
        redirect(url_for('admin.role_edit', id=id))
    return render_template("admin/role_edit.html", role_form=role_form, role=role)


@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    auth_form = AuthForm()
    if auth_form.validate_on_submit():
        data = auth_form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", "ok")
    return render_template("admin/auth_add.html", auth_form=auth_form)


@admin.route("/auth/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_list(page):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/auth_list.html", page_data=page_data)


@admin.route("/auth/del/<int:id>/")
@admin_login_req
@admin_auth
def auth_del(id=None):
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！", "ok")
    return redirect(url_for("admin.auth_list", page=1))


@admin.route("/auth/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    auth_form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if auth_form.validate_on_submit():
        data = auth_form.data
        auth.url = data['url']
        auth.name = data['name']
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！", "ok")
        redirect(url_for('admin.auth_edit', id=id))
    return render_template("admin/auth_edit.html", auth=auth, auth_form=auth_form)


@admin.route("/admin/add/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def admin_add():
    admin_form = AdminForm()
    from werkzeug.security import generate_password_hash
    if admin_form.validate_on_submit():
        data = admin_form.data
        admin = Admin(
            name=data['name'],
            pwd=generate_password_hash(data['pwd']),
            role_id=data['role_id'],
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！", "ok")
    return render_template("admin/admin_add.html", admin_form=admin_form)


@admin.route("/admin/list/<int:page>", methods=["GET"])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(
        Role
    ).filter(
        Role.id == Admin.role_id
    ).order_by(
        Admin.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template("admin/admin_list.html", page_data=page_data)
