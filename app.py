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
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

import os
from environs import Env
from datetime import timedelta
from uuid import uuid4

env = Env()
env.read_env()
app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(basedir, 'bank_auth.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
try:
    app.config["JWT_SECRET_KEY"] = env.str("JWT_SECRET_KEY")
except Exception:
    app.config["JWT_SECRET_KEY"] = "ajsdksadho3qy98hdjdkdsf64764837"
finally:

    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

jwt = JWTManager(app)
db = SQLAlchemy(app)


class Authentication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(60), nullable=False, unique=True)
    password = db.Column(db.String(260), nullable=False)


class Account_Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_no = db.Column(db.Integer, nullable=False)
    account_pin = db.Column(db.Integer, nullable=False)
    BankBalance = db.Column(db.Integer, default=0)


class Account_deposite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deposited = db.Column(db.Integer, nullable=False)
    account_pin = db.Column(db.Integer, nullable=False)


class Account_withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    withdrawal = db.Column(db.Integer, nullable=False)
    account_pin = db.Column(db.Integer, nullable=False)
    # BankBalance = db.Column(db.Integer, default=0)


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "data is not in json format"}), 401
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    if not name or not email or not password:
        return jsonify({"error": "All field are required"}), 400

    if "@" not in email:
        return jsonify({"error": "email is incorrect"}), 400
    if not name.strip():
        return jsonify({"error": "name not be empty!"}), 400
    if Authentication.query.filter_by(email=email).first():
        return jsonify({"error": "mail already exist "}), 400

    HashedPassword = generate_password_hash(password)
    new_auth = Authentication(name=name, email=email, password=HashedPassword)

    try:
        db.session.add(new_auth)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "email already exists"}), 409
    except Exception:
        db.session.rollback()
        return jsonify({"error": "something went wrong"}), 400
    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)
    return (
        jsonify(
            {
                "success": "user created successfully",
                "access-token": access_token,
                "refresh-token": refresh_token,
            }
        ),
        201,
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "data is not in json format"}), 401
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "All field are required"}), 400

    mail = Authentication.query.filter_by(email=email).first()

    if "@" not in email:
        return jsonify({"error": "email is incorrect"}), 400
    if not mail or not check_password_hash(mail.password, password):
        return jsonify({"error": "email or password is incorrect "}), 401

    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": new_access_token}), 200


@app.route("/home", methods=["GET"])
@jwt_required()
def home():
    email = get_jwt_identity()
    user = Authentication.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user not found"}), 401
    return jsonify({"name": user.name, "email": user.email}), 200


@app.route("/account", methods=["POST"])
@jwt_required()
def account():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "data is not in json format"}), 401
    account_no = data.get("account_no")
    account_pin = data.get("account_pin")
    if not account_no or not account_pin:
        return jsonify({"error": "All fields are required"}), 400
    if account_pin < 999 or account_pin > 10000:
        return jsonify({"error": "pin is size invalid"}), 400
    BankBalance = data.get("BankBalance")
    account_info = Account_Data(
        account_no=account_no, account_pin=account_pin, BankBalance=BankBalance
    )
    try:
        db.session.add(account_info)
        db.session.commit()
        return jsonify({"success": f"{BankBalance}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"This went wrong {e}"}), 400


@app.route("/deposit", methods=["POST"])
@jwt_required()
def deposit():
    data = request.get_json()
    if not data:
        return jsonify({"error": "data is not in json format"}), 401

    deposited = data.get("deposited")
    deposited_pin = data.get("account_pin")

    if not deposited or not deposited_pin:
        return jsonify({"error": "All fields are required"}), 400

    # Query by the pin provided in the request body
    account = Account_Data.query.filter_by(account_pin=deposited_pin).first()
    if not account:
        return jsonify({"error": "pin did not match. Try again."}), 422

    # Update the actual bank balance
    account.BankBalance += int(deposited)

    Deposit_Value = Account_deposite(deposited=deposited, account_pin=deposited_pin)
    try:
        db.session.add(Deposit_Value)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Something went wrong: {e}"}), 400

    return (
        jsonify(
            {"success": f"Deposited {deposited}. New Balance: {account.BankBalance}"}
        ),
        201,
    )


@app.route("/withdrawal", methods=["POST"])
@jwt_required()
def withdrawal():
    data = request.get_json()
    if not data:
        return jsonify({"error": "data is not in json format"}), 401
    withdrawal = data.get("withdrawal")
    withdrawal_pin = data.get("account_pin")
    if not withdrawal or not withdrawal_pin:
        return jsonify({"error": "withdrawl amount is required"}), 400
    withdrawal_pin = data.get("account_pin")
    account_withrawl_pin = Authentication.query.filter_by(
        account_pin=withdrawal_pin
    ).first()

    if not account_withrawl_pin:
        return jsonify({"error": "account pin is incorrect try again"})
    if withdrawal < account_withrawl_pin.BankBalance:
        return jsonify({"error": "your withdrawl amount is more than bankbalance"}), 400

    account_withrawl_pin.BankBalance -= withdrawal

    withdrawal_Value = Account_withdrawal(
        withdrawal=withdrawal, account_pin=withdrawal_pin
    )
    try:
        db.session.add(withdrawal_Value)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"This went wrong: {e}"}), 400
    return (
        jsonify(
            {
                "success": f"Your money is {withdrawal} now you have total of {account_withrawl_pin.BankBalance}"
            }
        ),
        201,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port="5002")
