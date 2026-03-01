from flask import Flask
from config import Config
from models import db
from flask_login import LoginManager

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return "Internal Control System Running"

if __name__ == "__main__":
    app.run()