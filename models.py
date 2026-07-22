from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone

# from sqlalchemy.exc.hybrid import hybrid_property
db = SQLAlchemy()


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(
        db.DateTime, default=datetime.now(timezone.utc).fromtimestamp
    )


class AdminLogin(db.Model):
    __tablename__ = "admin_login"
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(160), nullable=False)
    admin_email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    admin_password = db.Column(db.String(200), nullable=False)
    admin_created = db.Column(
        db.DateTime, default=datetime.now(timezone.utc).fromtimestamp
    )
    admin_updated = db.Column(
        db.DateTime, default=datetime.now, onupdate=datetime.now(timezone.utc)
    )
    banks = db.relationship(
        "Bank", lazy=True, backref="admin", cascade="all, delete-orphan"
    )


# @hybrid_property
# def total_bank(self):
#    return sum(bank.balance for bank in self.banks)


class Bank(db.Model):
    __tablename__ = "bank"
    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String(160), nullable=False)
    bank_address = db.Column(db.String(160), nullable=False)
    bank_created = db.Column(
        db.DateTime, default=datetime.now(timezone.utc).fromtimestamp
    )
    bank_updated = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.now(timezone.utc)
    )
    admin_id = db.Column(db.Integer, db.ForeignKey("admin_login.id"), nullable=False)

    user_accounts = db.relationship(
        "UserAccount", lazy=True, backref="bank", cascade="all, delete-orphan"
    )
    employee = db.relationship(
        "EmployeeLogin", lazy=True, backref="bank", cascade="all, delete-orphan"
    )


class EmployeeLogin(db.Model):
    __tablename__ = "employee_login"
    id = db.Column(db.Integer, primary_key=True)
    employee_name = db.Column(db.String(160), nullable=False)
    employee_email = db.Column(db.String(160), unique=True, nullable=False)
    employee_password = db.Column(db.String(200), nullable=False)
    employee_role = db.Column(db.String(160))
    employee_created = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    employee_updated = db.Column(
        db.DateTime, default=datetime.now(), onupdate=datetime(timezon.utc)
    )
    bank_id = db.Column(db.Integer, db.ForeignKey("bank.id"), nullable=False)


class UserLogin(db.Model):
    __tablename__ = "user_login"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(160), nullable=False)
    user_age = db.Column(db.Integer, nullable=False)
    user_email = db.Column(db.String(160), unique=True, nullable=False)
    user_password = db.Column(db.String(200), nullable=False)
    user_created = db.Column(
        db.DateTime, default=datetime.now(timezone.utc).fromtimestamp
    )
    user_updated = db.Column(
        db.DateTime, default=datetime.now(), onupdate=datetime.now(timezone.utc)
    )
    user_pin = db.Column(db.String(100), nullable=False)
    user_accounts = db.relationship(
        "UserAccount", lazy=True, backref="user", cascade="all, delete-orphan"
    )


class UserAccount(db.Model):
    __tablename__ = "user_accounts"
    id = db.Column(db.Integer, primary_key=True)
    user_account_number = db.Column(db.String(50), unique=True, nullable=False)
    user_created = db.Column(
        db.DateTime, default=datetime.now(timezone.utc).fromtimestamp
    )
    bank_balance = db.Column(db.Float, default=0.0)

    user_deposits = db.relationship(
        "UserDeposit", lazy=True, backref="useraccount", cascade="all, delete-orphan"
    )
    user_withdrawals = db.relationship(
        "UserWithdraw", lazy=True, backref="useraccount", cascade="all, delete-orphan"
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user_login.id"), nullable=False)
    bank_id = db.Column(db.Integer, db.ForeignKey("bank.id"), nullable=False)


class UserDeposit(db.Model):
    __tablename__ = "user_deposits"
    id = db.Column(db.Integer, primary_key=True)
    deposit_value = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(120), nullable=False, unique=True)
    Txn_date = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    user_account_id = db.Column(
        db.Integer, db.ForeignKey("user_accounts.id"), nullable=False
    )


class UserWithdraw(db.Model):
    __tablename__ = "user_withdrawals"
    id = db.Column(db.Integer, primary_key=True)
    withdrawal_value = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(120), nullable=False, unique=True)
    Txn_date = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    user_account_id = db.Column(
        db.Integer, db.ForeignKey("user_accounts.id"), nullable=False
    )
