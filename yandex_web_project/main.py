from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route('/')
def index():
    if 'user' in session:
        tasks = Task.query.filter_by(user_id=session['user']).all()
        return render_template('index.html', tasks=tasks)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if db.session.query(User).filter_by(username=username).count() < 1:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('login'))

    return render_template('reg.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('log.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user' in session:
        content = request.form['content']
        new_task = Task(content=content, user_id=session['user'])
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('index'))
    return redirect(url_for('login'))


@app.route('/delete_task/<int:id>')
def delete_task(id):
    if 'user' in session:
        task = Task.query.filter_by(id=id, user_id=session['user']).first()
        if task:
            db.session.delete(task)
            db.session.commit()
    return redirect(url_for('index'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()