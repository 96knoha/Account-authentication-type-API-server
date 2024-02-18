from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    nickname = db.Column(db.String(30), nullable=True)
    comment = db.Column(db.String(100), nullable=True)

    def __init__(self, user_id, password, nickname, comment):
        self.user_id = user_id
        self.password = password
        self.nickname = nickname
        self.comment = comment

    def __repr__(self):
        return f"<User {self.user_id}>"