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

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, 'bank.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = (
    "5Y4E3rlhAWL83q883ru5DwVUYpjglBU4FsJAMFWEqLs1e52ZJZuxrB3d64uYKbC77IttdMXv6KxdtnrMSw000cNdKkJWZCNxxaxV3WSIUcIEFFuxjeMKbKGjTwtWkF4F8stEF8QspWsyb5bCSsPZQPwPG"
)

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=20)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)
db.init_app(app)

email_list = ["@gmail.com", "@yahoo.com", "@outlook.com"]
def get_json_data():
    try:
        data = request.get_json(silent=True)
        if not data:
            return None, jsonify({"error": "Data is not in json format"}), 400
        return data, None, None
    except Exception as e:
        return None, jsonify({"error": f"Invalid request: {str(e)}"}), 400


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    claims = get_jwt()
    additional_claims = {"is_admin": claims.get("is_admin", False)}
    new_access_token = create_access_token(
        identity=current_user, additional_claims=additional_claims
    )
    return jsonify({"access_token": new_access_token}), 200


@jwt.token_in_blocklist_loader
def check_if_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return db.session.query(TokenBlocklist.id).filter_by(jti=jti).first() is not None


@app.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"msg": "logout successful"}), 200


# *Admin required decorator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("is_admin") is True:
                return fn(*args, **kwargs)
            return jsonify({"msg": "Administration access required."}), 403

        return decorator

    return wrapper


# *Admin
# ? Signup
@app.route("/admin_signup", methods=["POST"])
def admin_signup():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    admin_name = data.get("admin_name")
    admin_email = data.get("admin_email")
    admin_password = data.get("admin_password")

    if not admin_name or not admin_email or not admin_password:
        return jsonify({"error": "all fields are required"}), 400
    if not any(domain in admin_email for domain in email_list):
        return jsonify({"error": "Invalid email domain"}), 400

    if Admin_login.query.filter_by(admin_email=admin_email).first():
        return jsonify({"error": "Email already exists"}), 400
    HashedPassword = generate_password_hash(admin_password)
    new_admin = Admin_login(
        admin_name=admin_name,
        admin_email=admin_email,
        admin_password=HashedPassword,
    )

    try:
        db.session.add(new_admin)
        db.session.commit()
        access_token = create_access_token(
            identity=admin_email, additional_claims={"is_admin": True}
        )
        refresh_token = create_refresh_token(
            identity=admin_email, additional_claims={"is_admin": True}
        )

        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            201,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


@app.route("/admin_login", methods=["POST"])
def admin_login():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    admin_email = data.get("admin_email")
    admin_password = data.get("admin_password")

    user = Admin_login.query.filter_by(admin_email=admin_email).first()
    if not user or not check_password_hash(user.admin_password, admin_password):
        return jsonify({"error": "email or password is incorrect"}), 401

    access_token = create_access_token(
        identity=admin_email, additional_claims={"is_admin": True}
    )
    refresh_token = create_refresh_token(
        identity=admin_email, additional_claims={"is_admin": True}
    )
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


@app.route("/bank", methods=["POST"])
@admin_required()
def create_bank():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    bank_name = data.get("bank_name")
    bank_address = data.get("bank_address")

    current_admin_email = get_jwt_identity()
    admin = Admin_login.query.filter_by(admin_email=current_admin_email).first()

    if not bank_name or not bank_address:
        return jsonify({"error": "all fields are required"}), 400

    new_bank = Bank(bank_name=bank_name, bank_address=bank_address, admin_id=admin.id)
    try:
        db.session.add(new_bank)
        db.session.commit()
        return jsonify({"success": "Bank created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# * User Signup
@app.route("/user_signup", methods=["POST"])
def create_user():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    user_name = data.get("user_name")
    user_age = data.get("user_age")
    user_email = data.get("user_email")
    user_password = data.get("user_password")
    user_pin = data.get("user_pin")

    if not all([user_name, user_age, user_email, user_password, user_pin]):
        return jsonify({"error": "All fields are required"}), 400

    try:
        user_age = int(user_age)
    except (TypeError, ValueError):
        return jsonify({"error": "user_age must be a number"}), 400
    if user_age < 18:
        return jsonify({"error": "your age must be at least 18"}), 400
        if not any(domain in user_email for domain in email_list):
            return (
            jsonify({"error": f"email format is wrong, use only: {email_list}"}),
            400,
            )

    if (
        User_login.query.filter_by(user_email=user_email).first()
        or Admin_login.query.filter_by(admin_email=user_email).first()
    ):
        return jsonify({"error": "Email already exists"}), 400

    hashed_pw = generate_password_hash(user_password)
    hashed_pin = generate_password_hash(str(user_pin))
    new_user = User_login(
        user_name=user_name,
        user_age=user_age,
        user_email=user_email,
        user_password=hashed_pw,
        user_pin=hashed_pin,
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        access_token = create_access_token(
            identity=user_email, additional_claims={"is_admin": False}
        )
        refresh_token = create_refresh_token(
            identity=user_email, additional_claims={"is_admin": False}
        )
        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            201,
        )
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username already exists"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# * User login
@app.route("/user_login", methods=["POST"])
def userlogin():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    user_email = data.get("user_email")
    user_password = data.get("user_password")
    if not user_email or not user_password:
        return jsonify({"error": "all field are required"}), 400

    user = User_login.query.filter_by(user_email=user_email).first()
    if not user or not check_password_hash(user.user_password, user_password):
        return jsonify({"error": "email or password is incorrect"}), 401

    access_token = create_access_token(
        identity=user_email, additional_claims={"is_admin": False}
    )
    refresh_token = create_refresh_token(
        identity=user_email, additional_claims={"is_admin": False}
    )
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


# * User Account
@app.route("/user_account", methods=["POST"])
@jwt_required()
def create_user_account():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status
    user_account_number = data.get("user_account_number")
    bank_id = data.get("bank_id")
    initial_balance = data.get("bank_balance", 0.0)

    current_user_email = get_jwt_identity()
    user = User_login.query.filter_by(user_email=current_user_email).first()

    if not bank_id or not user_account_number:
        return jsonify({"error": "Bank ID and Account Number are required"}), 400
    if not Bank.query.get(bank_id):
        return jsonify({"error": "Bank does not exist"}), 404

    new_account = User_account(
        user_account_number=user_account_number,
        bank_balance=float(initial_balance),
        user_id=user.id,
        bank_id=bank_id,
    )
    try:
        db.session.add(new_account)
        db.session.commit()
        return jsonify({"success": "Bank account linked successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


@app.route("/user_deposit", methods=["POST"])
@jwt_required()
def user_deposit():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    deposit_value = data.get("deposit_value")
    pin = data.get("pin")
    account_id = data.get("account_id")
    if not deposit_value or not pin or not account_id:
        return jsonify({"error": "All fields are required"}), 400
    current_user_email = get_jwt_identity()
    user = User_login.query.filter_by(user_email=current_user_email).first()

    account = User_account.query.filter_by(id=account_id, user_id=user.id).first()
    if not account:
        return jsonify({"error": "Account not found or access denied"}), 404
    if not check_password_hash(user.user_pin, str(pin)):
        return jsonify({"error": "Invalid PIN credential validations"}), 401

    account.bank_balance += float(deposit_value)
    txn_id = f"DEP-{datetime.today().strftime('%Y%m%d%H%M')}-{uuid4().hex[:6]}"
    try:
        deposit_record = User_deposit(
            deposit_value=float(deposit_value),
            transaction_id=txn_id,
            user_account_id=account.id,
        )
        db.session.add(deposit_record)
        db.session.commit()
        return (
            jsonify(
                {
                    "success": f"{deposit_value} deposited successfully",
                    "transaction_id": txn_id,
                }
            ),
            200,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400

@app.route("/user_withdraw", methods=["POST"])
@jwt_required()
def user_withdraw():
    data, error_response, status = get_json_data()
    if error_response:
        return error_response, status

    withdrawal_value = data.get("withdrawal_value")
    pin = data.get("pin")
    account_id = data.get("account_id")
    if not withdrawal_value or not pin or not account_id:
        return jsonify({"error": "All fields are required"}), 400
    current_user_email = get_jwt_identity()
    user = User_login.query.filter_by(user_email=current_user_email).first()

    account = User_account.query.filter_by(id=account_id, user_id=user.id).first()
    if not account:
        return jsonify({"error": "Account not found or access denied"}), 404
    if not check_password_hash(user.user_pin, str(pin)):
        return jsonify({"error": "Invalid PIN"}), 401

    if float(withdrawal_value) > account.bank_balance:
        return jsonify({"error": "Insufficient funds available"}), 400
    account.bank_balance -= float(withdrawal_value)
    try:
        txn_id = f"WTH-{datetime.today().strftime('%Y%m%d%H%M')}-{uuid4().hex[:6]}"
        withdraw_record = User_withdraw(
            withdrawal_value=float(withdrawal_value),
            transaction_id=txn_id,
            user_account_id=account.id,
        )
        db.session.add(withdraw_record)
        db.session.commit()
        return (
            jsonify(
                {
                    "success": f"{withdrawal_value} withdrawn successfully",
                    "transaction_id": txn_id,
                }
            ),
            200,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=5002)