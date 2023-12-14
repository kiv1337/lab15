import os
from sqlalchemy.orm import relationship
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/delta/OneDrive/Рабочий стол/Учёба 407/Кочетков/lab15/database.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'

app.template_folder = os.path.abspath('templates')
app.config['UPLOAD_FOLDER'] = os.path.abspath('uploads')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    avatar_path = db.Column(db.String(255))
    
    
    def add_friend(self, friend):
        if not self.is_friend(friend):
            friendship = Friendship(user_id=self.id, friend_id=friend.id, status='pending')
            db.session.add(friendship)
            db.session.commit()

    def remove_friend(self, friend):
        friendship = Friendship.query.filter_by(user_id=self.id, friend_id=friend.id).first()
        if friendship:
            db.session.delete(friendship)
            db.session.commit()

    def is_friend(self, user):
        return Friendship.query.filter_by(user_id=self.id, friend_id=user.id, status='accepted').first() is not None

    @property
    def friends_list(self):
        friend_ids = [friendship.friend_id for friendship in Friendship.query.filter_by(user_id=self.id, status='accepted').all()]
        return User.query.filter(User.id.in_(friend_ids))



class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    file_path = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])



with app.app_context():
    db.create_all()

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = None
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)

        if user:
            return func(*args, **kwargs)

        return redirect(url_for('login'))

    return wrapper

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/auth/', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('user'))    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')

        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar.filename != '':
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar.filename)
                avatar.save(avatar_path)
            else:
                avatar_path = None
        else:
            avatar_path = None

        new_user = User(username=username, password_hash=hashed_password, avatar_path=avatar_path)
        if username == 'admin' and password == 'admin':
            new_user.admin = True
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('auth.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('user'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('user'))
        else:
            return render_template('auth.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/user/')
@login_required
def user():
    user_id = session['user_id']
    user = User.query.get(user_id)
    return render_template('user.html', user=user)

    
    
@app.route('/change_avatar', methods=['POST'])
@login_required
def change_avatar():
        user_id = session['user_id']
        user = User.query.get(user_id)

        if 'avatar' in request.files:
            new_avatar = request.files['avatar']
            if new_avatar.filename != '':
                new_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], new_avatar.filename)
                new_avatar.save(new_avatar_path)
                user.avatar_path = new_avatar_path
                db.session.commit()

        return redirect(url_for('user'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/user_list', methods=['GET'])
@login_required
def user_list():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        if current_user.admin:
            users = User.query.all()
            return render_template('user_list.html', users=users)
        else:
            abort(403)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        if current_user.admin:
            user_to_edit = User.query.get(user_id)
            if request.method == 'POST':
                user_to_edit.username = request.form['username']
                user_to_edit.admin = request.form.get('admin', False)
                db.session.commit()
                return redirect(url_for('user_list'))
            return render_template('edit_user.html', user_to_edit=user_to_edit)
        else:
            abort(403)


@app.route('/delete_user/<int:user_id>', methods=['GET'])
@login_required
def delete_user(user_id):

        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        if current_user.admin:
            user_to_delete = User.query.get(user_id)
            db.session.delete(user_to_delete)
            db.session.commit()
            return redirect(url_for('user_list'))
        else:
            abort(403)

#Мессенджер

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)
        if request.method == 'POST':
            friend_username = request.form['friend_username']
            friend = User.query.filter_by(username=friend_username).first()
            if friend:
                current_user.add_friend(friend)
        return render_template('friends.html', current_user=current_user)
    

@app.route('/friend_requests', methods=['GET'])
@login_required
def friend_requests():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)
        friend_requests = Friendship.query.filter_by(friend_id=current_user.id, status='pending').all()
        return render_template('friend_requests.html', friend_requests=friend_requests, User=User)



@app.route('/accept_friend_request/<int:request_id>', methods=['GET'])
def accept_friend_request(request_id):
    friendship_request = Friendship.query.get(request_id)
    if friendship_request:
        friendship_request.status = 'accepted'
        new_friendship = Friendship(user_id=friendship_request.friend_id, friend_id=friendship_request.user_id, status='accepted')
        db.session.add(new_friendship)
        db.session.commit()
    return redirect(url_for('friend_requests'))


@app.route('/reject_friend_request/<int:request_id>', methods=['GET'])
def reject_friend_request(request_id):
    friendship_request = Friendship.query.get(request_id)
    db.session.delete(friendship_request)
    db.session.commit()
    return redirect(url_for('friend_requests'))

@app.route('/dialogs', methods=['GET'])
@login_required
def dialogs():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)
        dialog_partners = current_user.friends_list
        return render_template('dialogs.html', dialog_partners=dialog_partners)


def extract_filename(file_path):
    return os.path.basename(file_path)

@app.route('/dialog/<int:partner_id>', methods=['GET', 'POST'])
@login_required
def dialog(partner_id):
    current_user_id = session['user_id']
    current_user = User.query.get(current_user_id)
    partner = User.query.get(partner_id)
    if request.method == 'POST':
        message_content = request.form['message_content']
        new_message = Message(sender_id=current_user.id, recipient_id=partner.id, content=message_content)
        
        if 'message_file' in request.files:
            message_file = request.files['message_file']
            if message_file.filename != '':
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], message_file.filename)
                message_file.save(file_path)
                new_message.file_path = file_path

        db.session.add(new_message)
        db.session.commit()
        
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == partner.id)) |
        ((Message.sender_id == partner.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    return render_template('dialog.html', partner=partner, messages=messages, extract_filename=extract_filename)


@app.route('/remove_friend', methods=['POST'])
@login_required
def remove_friend():
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)
        
        friend_id = request.form.get('friend_id')
        friend = User.query.get(friend_id)

        if friend and current_user.is_friend(friend):
            current_user.remove_friend(friend)
            friend.remove_friend(current_user)


migrate = Migrate(app, db)
if __name__ == '__main__':
    app.run(debug=True)
