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
import os
from datetime import timedelta, datetime
from models import db, Bank, UserAccount
from models import (
    TokenBlocklist,
    AdminLogin,
    Bank,
    EmployeeLogin,
    UserLogin,
    UserAccount,
    UserDeposit,
    UserWithdraw,
    db,
)
from functools import wraps
from uuid import uuid4
from dotenv import load_dotenv
from environs import Env
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
env = Env()
env.read_env()
load_dotenv()

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(basedir, 'bank.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=20)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

# *Rate limiter code
limiter = Limiter(
    application,
    key_func=get_remote_address,
    default_limits=["200 per day", "30 per hour"]
)
jwt = JWTManager(app)
db.init_app(app)

# *All the listed emails that are allow
email_list = ["@gmail.com", "@yahoo.com", "@outlook.com"]
employee_roles = [
    "manager",
    "DeskWorker",
    "SubAdmin",
    "Accountant",
    "Waltchecker",
    "Maintainer",
]

# *Get data in json format only
def get_json_data():
    try:
        data = request.get_json(silent=True)
        if not data:
            return None, jsonify({"error": "Data is not in json format"}), 400
        return data, None, None
    except Exception as e:
        return None, jsonify({"error": f"Invalid request: {e}"}), 400


# *Refresh
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    claims = get_jwt()
    additional_claims = {
        "is_admin": claims.get("is_admin", False),
        "is_employee": claims.get("is_employee", False),
        "is_user": claims.get("is_user", False),
    }
    new_access_token = create_access_token(
        identity=current_user, additional_claims=additional_claims
    )
    return jsonify({"access_token": new_access_token}), 200


# *BlockList
@jwt.token_in_blocklist_loader
def check_if_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return db.session.query(TokenBlocklist.id).filter_by(jti=jti).first() is not None


# *Logout
@app.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"msg": "logout successful"}), 200

# *404 - page not found
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"msg": "404 - Page not found"}), 404


# *Admin required decorator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            is_admin = claims.get("is_admin", False)
            if is_admin is True:
                return fn(*args, **kwargs)
            return jsonify({"msg": "Administration access required."}), 403

        return decorator

    return wrapper


# *Employee required decorator
def emp_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            # Check BOTH conditions using an OR statement
            is_employee = claims.get("is_employee", False)
            if is_employee is True:
                return fn(*args, **kwargs)
            return jsonify({"msg": "Employee access required."}), 403

        return decorator

    return wrapper


# -------------------------------------------------------------------
# *Admin - Signup
@app.route("/admin_signup", methods=["POST"])
@limiter.limit("10 per minute")
def admin_signup():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    admin_name = data.get("admin_name")
    admin_email = data.get("admin_email")
    admin_password = data.get("admin_password")

    if not admin_name or not admin_email or not admin_password:
        return jsonify({"error": "all fields are required"}), 400
    if not admin_email.endswith(tuple(email_list)):
        return jsonify({"error": "Invalid email domain"}), 400

    if AdminLogin.query.filter_by(admin_email=admin_email).first():
        return jsonify({"error": "Email already exists"}), 400
    HashedPassword = generate_password_hash(admin_password)
    new_admin = AdminLogin(
        admin_name=admin_name,
        admin_email=admin_email,
        admin_password=HashedPassword,
    )

    try:
        db.session.add(new_admin)
        db.session.commit()

        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            201,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Some error occured"}), 400


# *Admin - Login
@app.route("/admin_login", methods=["POST"])
def admin_login():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

    admin_email = data.get("admin_email")
    admin_password = data.get("admin_password")

    user = AdminLogin.query.filter_by(admin_email=admin_email).first()
    if not user or not check_password_hash(user.admin_password, admin_password):
        return jsonify({"error": "email or password is incorrect"}), 401

    access_token = create_access_token(
        identity=admin_email, additional_claims={"is_admin": True}
    )
    refresh_token = create_refresh_token(
        identity=admin_email, additional_claims={"is_admin": True}
    )
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


# *Employee - signup
@app.route("/employee_signup", methods=["POST"])
@admin_required()
def employee_signup():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    employee_name = data.get("employee_name")
    employee_email = data.get("employee_email")
    employee_password = data.get("employee_password")
    employee_role = data.get("employee_role")
    bank_id = data.get("bank_id")
    if (
        not employee_name
        or not employee_email
        or not employee_password
        or not employee_role
        or not bank_id
    ):
        return jsonify({"error": "all fields are required"}), 400
    if not db.session.get(Bank, bank_id):
        return jsonify({"error": "Bank does not exist"}), 404
    if not employee_email.endswith(tuple(email_list)):
        return jsonify({"error": f"email format is wrong, use {email_list}"}), 400
    if  (
        AdminLogin.query.filter_by(admin_email=employee_email).first()
        or UserLogin.query.filter_by(user_email=employee_email).first()
        or EmployeeLogin.query.filter_by(employee_email=employee_email).first()
    ):
        return jsonify({"error": "email already exist"}), 400
    if employee_role not in employee_roles :
        return jsonify({"error": "For now this role does not exist"}), 404
    hashed_password = generate_password_hash(employee_password)
    new_employee = EmployeeLogin(
        employee_name=employee_name,
        employee_email=employee_email,
        employee_password=hashed_password,
        employee_role=employee_role,
        bank_id=bank_id,
    )
    try:
        db.session.add(new_employee)
        db.session.commit()
        access_token = create_access_token(
            identity=employee_email, additional_claims={"is_employee": True}
        )
        refresh_token = create_refresh_token(
            identity=employee_email, additional_claims={"is_employee": True}
        )
        return (
            jsonify({"access_token": access_token, "refresh_token": refresh_token}),
            201,
        )
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"{"Some error occured"}"}), 400


# *Employee - login
@app.route("/employee_login", methods=["POST"])
def employee_login():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    employee_email = data.get("employee_email")
    employee_password = data.get("employee_password")
    if not employee_email or not employee_password:
        return jsonify({"error": "all fields are required"}), 400
    user = EmployeeLogin.query.filter_by(employee_email=employee_email).first()
    if not user or not check_password_hash(user.employee_password, employee_password):
        return jsonify({"error": "email or passwords are incorrect"}), 401
    access_token = create_access_token(
        identity=employee_email, additional_claims={"is_employee": True}
    )
    refresh_token = create_refresh_token(
        identity=employee_email, additional_claims={"is_employee": True}
    )
    return jsonify({"access_token": access_token, "refresh_token": refresh_token})


# *Bank
@app.route("/bank", methods=["POST"])
@admin_required()
def create_bank():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    bank_name = data.get("bank_name")
    bank_address = data.get("bank_address")
    current_admin_email = get_jwt_identity()
    admin = AdminLogin.query.filter_by(admin_email=current_admin_email).first()
    if not bank_name or not bank_address:
        return jsonify({"error": "all fields are required"}), 400

    new_bank = Bank(bank_name=bank_name, bank_address=bank_address, admin_id=admin.id)
    try:
        db.session.add(new_bank)
        db.session.commit()
        return jsonify({"success": "Bank created successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Some error occured"}), 400


# *User - Signup
@app.route("/user_signup", methods=["POST"])
@emp_required()
def create_user():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

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
    if not user_email.endswith(tuple(email_list)):
        return (
            jsonify({"error": f"email format is wrong, use only: {email_list}"}),
            400,
        )

    if (
        UserLogin.query.filter_by(user_email=user_email).first()
        or AdminLogin.query.filter_by(admin_email=user_email).first()
    ):
        return jsonify({"error": "Email already exists"}), 400

    hashed_pw = generate_password_hash(user_password)
    hashed_pin = generate_password_hash(str(user_pin))
    new_user = UserLogin(
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
        return jsonify({"error": "Some error occured"}), 400


# *User - login
@app.route("/user_login", methods=["POST"])
def userlogin():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

    user_email = data.get("user_email")
    user_password = data.get("user_password")
    if not user_email or not user_password:
        return jsonify({"error": "all field are required"}), 400

    user = UserLogin.query.filter_by(user_email=user_email).first()
    if not user or not check_password_hash(user.user_password, user_password):
        return jsonify({"error": "email or password is incorrect"}), 401

    access_token = create_access_token(
        identity=user_email, additional_claims={"is_admin": False}
    )
    refresh_token = create_refresh_token(
        identity=user_email, additional_claims={"is_admin": False}
    )
    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


# *User - Account
@app.route("/user_account", methods=["POST"])
@emp_required()
def create_user_account():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    user_account_number = data.get("user_account_number")
    bank_id = data.get("bank_id")
    initial_balance = data.get("bank_balance", 0.0)

    current_user_email = get_jwt_identity()
    user = UserLogin.query.filter_by(user_email=current_user_email).first()

    if not bank_id or not user_account_number:
        return jsonify({"error": "Bank ID and Account Number are required"}), 400
    if not db.session.get(Bank, bank_id):
        return jsonify({"error": "Bank id Does not exist"}), 404
    new_account = UserAccount(
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
        return jsonify({"error": "Some error occured"}), 400


# *User Deposite
@app.route("/user_deposit", methods=["POST"])
@jwt_required()
def user_deposit():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

    deposit_value = data.get("deposit_value")
    pin = data.get("pin")
    account_id = data.get("account_id")
    if not deposit_value or not pin or not account_id:
        return jsonify({"error": "All fields are required"}), 400
    current_user_email = get_jwt_identity()
    user = UserLogin.query.filter_by(user_email=current_user_email).first()

    account = UserAccount.query.filter_by(id=account_id, user_id=user.id).first()
    if not account:
        return jsonify({"error": "Account not found or access denied"}), 404
    if not check_password_hash(user.user_pin, str(pin)):
        return jsonify({"error": "Invalid PIN credential validations"}), 401

    account.bank_balance += float(deposit_value)
    txn_id = f"DEP-{datetime.today().strftime('%Y%m%d%H%M')}-{uuid4().hex[:6]}"
    try:
        deposit_record = UserDeposit(
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
        return jsonify({"error": "Some error occured"}), 400


# *User - Withdraw
@app.route("/user_withdraw", methods=["POST"])
@jwt_required()
def user_withdraw():
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

    withdrawal_value = data.get("withdrawal_value")
    pin = data.get("pin")
    account_id = data.get("account_id")
    if not withdrawal_value or not pin or not account_id:
        return jsonify({"error": "All fields are required"}), 400
    current_user_email = get_jwt_identity()
    user = UserLogin.query.filter_by(user_email=current_user_email).first()

    account = UserAccount.query.filter_by(id=account_id, user_id=user.id).first()
    if not account:
        return jsonify({"error": "Account not found or access denied"}), 404
    if not check_password_hash(user.user_pin, str(pin)):
        return jsonify({"error": "Invalid PIN"}), 401

    if float(withdrawal_value) > account.bank_balance:
        return jsonify({"error": "Insufficient funds available"}), 400
    account.bank_balance -= float(withdrawal_value)
    try:
        txn_id = f"WTH-{datetime.today().strftime('%Y%m%d%H%M')}-{uuid4().hex[:6]}"
        withdraw_record = UserWithdraw(
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
        return jsonify({"error": "Some error occured"}), 400


# *GET --  BY ID
# ! Admin
@app.route("/admin/<int:id>", methods=["GET"])
@admin_required()
@limiter.limit("10 per minute")
def admin_get(id):
    Admin = AdminLogin.query.get(id)
    if Admin:
        return (
            jsonify(
                {
                    "name": Admin.admin_name,
                    "Email": Admin.admin_email,
                    "Starting Date": Admin.admin_created,
                    "Total banks": len(Admin.banks),
                    "Bank": [
                        {
                            "NO": bank.id,
                            "Name": bank.bank_name,
                            "Created": bank.bank_created,
                            "Total Employees": len(bank.employee),
                            # "Total users": sum(bank.user_accounts),
                            "Employees": [
                                {"No": emp.id, "emp": emp.employee_name}
                                for emp in bank.employee
                            ],
                        }
                        for bank in Admin.banks
                    ],
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Admin ID not found"}), 404


# ! Bank
@app.route("/bank/<int:id>", methods=["GET"])
@limiter.limit("12 per minute")
@admin_required()
def get_bank(id):
    bank = Bank.query.get(id)
    if bank:
        return (
            jsonify(
                {
                    "Bank name": bank.bank_name,
                    "Bank Address": bank.bank_address,
                    "Created": bank.bank_created,
                    "Total Employees": len(bank.employee),
                    "Employees": [
                        {
                            "NO": emps.id,
                            "Name": emps.employee_name,
                            "Role": emps.employee_role,
                        }
                        for emps in bank.employee
                    ],
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Bank not found"}), 404


# ! Employees
@app.route("/employee/<int:id>", methods=["GET"])
@admin_required()
def get_employee(id):
    emps = EmployeeLogin.query.get(id)
    if emps:
        return (
            jsonify(
                {
                    "No": emps.id,
                    "Name": emps.employee_name,
                    "Email": emps.employee_email,
                    "Role": emps.employee_role,
                    "Joined": emps.employee_created,
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Employee not found"}), 404


# ! Users
@app.route("/user/<int:id>", methods=["GET"])
@limiter.exempt
def get_user(id):
    users = UserLogin.query.get(id)
    if users:
        return jsonify(
            {
                "No": users.id,
                "Name": users.user_name,
                "Email": users.user_email,
                "Joined": users.user_created,
                "Accounts": [
                    {
                        "No": account.id,
                        "Account Number": account.user_account_number,
                        "Bank Balance": account.bank_balance,
                        "All the Transactions": [
                            {
                                "Withdraw": [
                                    {
                                        "Transation-id": withdraw.transaction_id,
                                        "Amount": withdraw.withdrawal_value,
                                        "Date": withdraw.Txn_date,
                                    }
                                    for withdraw in account.UserWithdraw
                                ],
                                "Deposite": [
                                    {
                                        "Transation-id": deposit.transaction_id,
                                        "Amount": deposit.deposit_value,
                                        "Date": deposit.Txn_date,
                                    }
                                    for deposit in account.UserDeposit
                                ],
                            }
                        ],
                    }
                    for account in users.UserAccount
                ],
            }
        )
    else:
        return jsonify({"error": "User not found"}), 404


# *PUT


# ! Admin
@app.route("/admin/<int:id>", methods=["PUT"])
@admin_required()
@limiter.limit("1/20days")
def put_admin(id):
    Admin = AdminLogin.query.get(id)
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    if Admin:
        Admin_provided_password = data.get("admin_password")
        if not Admin_provided_password:
            return jsonify("Password not provided"), 404
        if check_password_hash(admin.admin_password, Admin_provided_password):

            Admin.admin_name = data.get("name", Admin.admin_name)
            Admin.admin_email = data.get("email", Admin.admin_email)

            db.session.commit()
            return (
                jsonify(
                    {
                        "Success": f"{Admin.admin_name}'s data has been updated ",
                        "Update At": Admin.admin_updated(isformated),
                    }
                ),
                204,
            )
        else:
            return jsonify({"error": "Admin password is incorrect"}), 401
    else:
        return jsonify({"error": "Admin not found"}), 404


# ! Bank
@app.route("/bank/<int:id>", methods=["PUT"])
@admin_required()
@limiter.limit("1/30days")
def put_bank(id):
    bank = Bank.query.get(id)
    if not bank:
        return jsonify({"error": "Bank id not found"}), 404
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status

    Admin_provided_password = data.get("admin_password")
    admin = AdminLogin.query.get("password")
    if not admin:
        return jsonify({"error": "Admin not password "}), 401
    if check_password_hash(admin.admin_password, Admin_provided_password):
        bank.bank_name = data.get("name", bank.bank_name)
        bank.bank_address = data.get("bank_address", bank.bank_address)
        bank.bank_updated = datetime.now(timezone.utc)
        db.session.commit()
        return (
            jsonify(
                {
                    "success": f"{bank.bank_name}'s data has been updated ",
                    "Update At": bank.bank_updated.isoformat(),
                }
            ),
            204,
        )
    else:
        return jsonify({"error": "Admin password is incorrect"}), 401


@app.route("/employee/<int:id>", methods=["PUT"])
@admin_required()
@limiter.limit("1/100days")
def put_employee(id):
    Employee = EmployeeLogin.query.get(id)
    data, format_response, status = get_json_data()
    if Employee:
        emp_provide_password = AdminLogin.query.get("admin_password")
        if not emp_provide_password:
            return jsonify({"error": "Employee's password is not provided"}), 401
        if check_password_hash(Employee.employee_password, emp_provide_password):
            Employee.employee_name = data.get("name", Employee.employee_name)
            Employee.employee_email = data.get("email", Employee.employee_email)
            Employee.employee_role = data.get("role", Employee.employee_role)
            Employee.employee_updated = datetime.now(timezone.utc)
            db.session.commit()
            return jsonify(
                {
                    "success": f"{Employee.employee_name}'s data has been updated ",
                    "Update AT": Employee.employee_updated.isoformat(),
                }
            )
        else:
            return jsonify({"error": "Employee password is incorrect"}), 401

    else:
        return jsonify({"error": "Employee not found"}), 404


@app.route("/<int:id>", methods=["PUT"])
@emp_required()
@limiter.limit("1/14days")
def put_user(id):
    User = UserLogin.get(id)
    data, format_response, status = get_json_data()
    if format_response:
        return format_response, status
    if User:
        User.user_name = data.get("name", User.user_name)
        User.user_email = data.get("email", User.user_email)
        User.user_updated = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify(
            {
                "sucess": f"{User.user_name}'s data has been updated ",
                "Updated At": user.user_updated.isformated(),
            }
        )
    else:
        return jsonify({"error": "User not found "}), 404


# *Delete by id
# ! Admin
@app.route("/admin/<int:id>", methods=["DELETE"])
@admin_required()
def delete_admin(id):
    Admin = AdminLogin.query.get(id)
    data, formated, status = get_json_data()
    if formated:
        return formated, status
    if Admin:
        admin_id, admin_name = Admin, Admin.admin_name

        db.session.delete(Admin)
        db.session.commit()
        db.session.close()
        return (
            jsonify(
                {
                    "delete": f"{admin_name} with id {admin_id} has been deleted successfully from database"
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Admin not found"}), 404


# ! Bank
@app.route("/bank/<int:id>", methods=["DELETE"])
@admin_required()
def delete_bank(id):
    bank = Bank.query.get(id)
    data, formated, status = get_json_data()
    if formated:
        return formated, status
    if bank:
        bank_id, bank_name = bank, Bank.bank_name
        db.session.delete(bank)
        db.session.commit()
        db.commit()
        return (
            jsonify(
                {
                    "delete": f"{bank_name} with id {bank_id} has been deleted successfully from database"
                }
            ),
            200,
        )
    else:
        return ({"error": "Bank not found "}), 404


# ! Employee
@app.route("/employee/<int:id>", methods=["DELETE"])
@admin_required()
def delete_employee(id):
    employee = EmployeeLogin.query.get(id)
    data, formated, status = get_json_data()
    if formated:
        return formated, status
    if employee:
        employee_id, employee_name = employee, employee.employee_name
        db.session.delete(employee)
        db.session.commit()
        db.session.close()
        return (
            jsonify(
                {
                    "delete": f"{employee_name} with id {employee_id} has been deleted successfully from database"
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Employee not found"}), 404


# ! User
@app.route("/user/<int:id>", methods=["DELETE"])
@emp_required()
def delete_user(id):
    user = UserLogin.query.get(id)
    # user_account    = UserAccount.query.get(id)
    # user_deposit    = UserDeposit.query.get(id)
    # user_withdraw   = UserWithdraw.query.get(id)
    data, formated, status = get_json_data()
    if formated:
        return formated, status
    if user:
        user_id, user_name = user, user.user_name
        db.session.delete(user)
        db.session.commit()
        db.session.close()
        return (
            jsonify(
                {
                    "delete": f"{user_name} with id {user_id} has been deleted successfully from database"
                }
            ),
            200,
        )
    else:
        return jsonify({"error", "User not found "}), 404


@app.route("/admin-acc/<int:id>", methods=["DELETE"])
def delete_user_acc(id):
    user_account = UserAccount.query.get(id)
    data, formated, status = get_json_data()
    if formated:
        return formated, status
    if user_account:
        user_account_id, user_acc_no = user_account, user_account.user_account_number
        db.session.delete(user_account)
        db.session.commit()
        db.session.close()
        return (
            {
                "error": f"{user_acc_no} number with id {user_account_id} has been deleted successfully from database"
            }
        ), 200
    else:
        return jsonify({"error": "User not found "}), 404


# *Runner
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(port=5002)
