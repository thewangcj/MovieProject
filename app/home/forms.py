# -*- coding: utf-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Email, Regexp
from app.models import User


class RegisterForm(FlaskForm):
    name = StringField(
        label="昵称",
        validators=[
            DataRequired("请输入昵称！")
        ],
        description="昵称",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入昵称！",
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码！",
        }
    )
    re_pwd = PasswordField(
        label="确认密码",
        validators=[
            DataRequired("请输入确认密码！"),
            EqualTo('pwd', message="两次密码不一致！")
        ],
        description="确认密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入确认密码！",
        }
    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱！",
        }
    )
    phone = StringField(
        label="手机号",
        validators=[
            DataRequired("请输入手机号！"),
            Regexp("1[3458]\d{9}", message="手机号格式不正确!")
        ],
        description="手机号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入手机号！",
        }
    )
    submit = SubmitField(
        "注册",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    def validate_name(self, field):
        name = field.data
        user_count = User.query.filter_by(name=name).count()
        if user_count == 1:
            raise ValidationError("昵称重复！")

    def validate_email(self, field):
        email = field.data
        email_count = User.query.filter_by(email=email).count()
        if email_count == 1:
            raise ValidationError("邮箱重复！")

    def validate_phone(self, field):
        phone = field.data
        phone_count = User.query.filter_by(phone=phone).count()
        if phone_count == 1:
            raise ValidationError("手机号重复！")


class LoginForm(FlaskForm):
    account = StringField(
        label="账号",
        validators=[
            DataRequired("请输入账号！")
        ],
        description="账号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入账号！"
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码！"
        }
    )
    submit = SubmitField(
        "登录",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )


class UserForm(FlaskForm):
    name = StringField(
        label="昵称",
        validators=[
            DataRequired("请输入昵称！")
        ],
        description="昵称",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入昵称！",
        }
    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱！",
        }
    )
    phone = StringField(
        label="手机号",
        validators=[
            DataRequired("请输入手机号！"),
            Regexp("1[3458]\d{9}", message="手机号格式不正确!")
        ],
        description="手机号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入手机号！",
        }
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired("请输入简介")
        ],
        description="简介",
        render_kw={
            "class": "form-control",
            "rows": 10,
            "id": "input_info"
        }
    )
    face = FileField(
        label="头像",
        validators=[
            DataRequired("请上传头像")
        ],
        description="头像",
        render_kw={
            "id": "input_face"
        }
    )
    submit = SubmitField(
        '提交',
        render_kw={
            "class": "btn btn-success"
        }
    )


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码！")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码！",
            "id": "input_pwd"
        }
    )
    new_pwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired("请输入新密码！")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码！",
            "id": "input_newpwd"
        }
    )
    submit = SubmitField(
        "修改",
        render_kw={
            "class": "btn btn-primary glyphicon glyphicon-edit"
        }
    )

class CommentForm(FlaskForm):
    content = TextAreaField(
        label="评论内容",
        validators=[
            DataRequired("请输入评论内容！")
        ],
        description="评论内容",
        render_kw={
            "placeholder": "请输入评论内容！",
            "id": "input_content",
            "class": "form-control",
            "row":10
        }
    )
    submit = SubmitField(
        "提交评论",
        render_kw={
            "class": "btn btn-success glyphicon glyphicon-edit",
            "id":"btn-sub"
        }
    )
