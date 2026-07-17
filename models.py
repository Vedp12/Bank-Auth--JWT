from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone

db = SQLAlchemy()


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class Admin_login(db.Model):
    __tablename__ = "admin_login"
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(160), nullable=False)
    admin_email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    admin_password = db.Column(db.String(150), nullable=False)
    admin_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    banks = db.relationship("Bank", lazy=True, backref="admin")


class Bank(db.Model):
    __tablename__ = "banks"
    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String(160), nullable=False)
    bank_address = db.Column(db.String(160), nullable=False)
    bank_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    admin_id = db.Column(db.Integer, db.ForeignKey("admin_login.id"), nullable=False)
    user_accounts = db.relationship("User_account", lazy=True, backref="bank")


class User_login(db.Model):
    __tablename__ = "user_login"
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(160), nullable=False)
    user_age = db.Column(db.Integer, nullable=False)
    user_email = db.Column(db.String(160), unique=True, nullable=False)
    user_password = db.Column(db.String(150), nullable=False)
    user_created = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user_pin = db.Column(db.String(100), nullable=False)
    user_accounts = db.relationship("User_account", lazy=True, backref="user")


class User_account(db.Model):
    __tablename__ = "user_accounts"
    id = db.Column(db.Integer, primary_key=True)
    user_account_number = db.Column(db.String(50), unique=True, nullable=False)
    bank_balance = db.Column(db.Float, default=0.0)

    user_deposits = db.relationship("User_deposit", lazy=True, backref="useraccount")
    user_withdrawals = db.relationship(
        "User_withdraw", lazy=True, backref="useraccount"
    )

    user_id = db.Column(db.Integer, db.ForeignKey("user_login.id"), nullable=False)
    bank_id = db.Column(db.Integer, db.ForeignKey("banks.id"), nullable=False)


class User_deposit(db.Model):
    __tablename__ = "user_deposits"
    id = db.Column(db.Integer, primary_key=True)
    deposit_value = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(120), nullable=False, unique=True)
    transaction_date = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    user_account_id = db.Column(
        db.Integer, db.ForeignKey("user_accounts.id"), nullable=False
    )


class User_withdraw(db.Model):
    __tablename__ = "user_withdrawals"
    id = db.Column(db.Integer, primary_key=True)
    withdrawal_value = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(120), nullable=False, unique=True)
    transaction_date = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    user_account_id = db.Column(
        db.Integer, db.ForeignKey("user_accounts.id"), nullable=False
    )
