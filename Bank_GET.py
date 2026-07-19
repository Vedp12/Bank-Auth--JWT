from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt,
    get_jwt_identity,
)
from sqlalchemy.exc import IntegrityError
import os
from datetime import timedelta, datetime
from models import db
from models import *
from functools import wraps
from uuid import uuid4
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, 'bank.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
import os

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=20)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)
db.init_app(app)

