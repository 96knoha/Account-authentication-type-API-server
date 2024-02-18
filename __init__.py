from flask import Flask
import bcrypt
from models import db, User

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 

db.init_app(app)

with app.app_context():
    if not User.query.filter_by(user_id="TaroYamada").first():
        user_id = "TaroYamada"
        password = "PaSSwd4TY"
        nickname = "たろー"
        comment = "僕は元気です"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(user_id=user_id, password=hashed_password, nickname=nickname, comment=comment)

        db.session.add(new_user)
        db.session.commit()

