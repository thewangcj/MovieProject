# -*- coding: utf-8 -*-
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_redis import FlaskRedis
import pymysql
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:root@127.0.0.1:3306/movie"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = "febb3f74a7c84d6bba113bdf9a5e0e2b"
app.config["REDIS_URL"] = "redis://@localhost:6379/0"
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)),"static/uploads/")
app.config["USER_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)),"static/uploads/users/")

app.debug = True
db = SQLAlchemy(app)
rd = FlaskRedis(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")


@app.errorhandler(404)
def page_not_found(error):
    return render_template("home/404.html"), 404

# db = SQLAlchemy()


# def create_app():
#     app = Flask(__name__)
#     app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:root@127.0.0.1:3306/movie"
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
#     app.config["SECRET_KEY"] = "febb3f74a7c84d6bba113bdf9a5e0e2b"
#
#     app.debug = True
#     db.init_app(app)
#
#     from app.home import home as home_blueprint
#     from app.admin import admin as admin_blueprint
#
#     app.register_blueprint(home_blueprint)
#     app.register_blueprint(admin_blueprint, url_prefix="/admin")
#
#     @app.errorhandler(404)
#     def page_not_found(error):
#         return render_template("home/404.html"), 404
#
#     return app
