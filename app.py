from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_bcrypt import Bcrypt
import os
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask import session
from flask_wtf.csrf import generate_csrf
from flask import abort

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # family, lifestyle, values, likes
    type = db.Column(db.String(10), nullable=False, default='scale')  # 'scale' or 'yesno'

# Response model
class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer = db.Column(db.Integer, nullable=False)  # 0-10

    user = db.relationship('User', backref=db.backref('responses', lazy=True))
    question = db.relationship('Question', backref=db.backref('responses', lazy=True))

# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Admin: Add Question Form
class QuestionForm(FlaskForm):
    text = StringField('Question Text', validators=[DataRequired(), Length(max=500)])
    category = SelectField('Category', choices=[
        ('family_living', 'Family & Living Arrangements'),
        ('finances_lifestyle', 'Finances & Lifestyle'),
        ('culture_religion', 'Culture, Religion & Traditions'),
        ('values_decision', 'Values & Decision-Making'),
        ('career_ambitions', 'Career & Ambitions'),
        ('children_pets', 'Children, Pets & Parenting'),
        ('dealbreakers', 'Dealbreakers')
    ], validators=[DataRequired()])
    type = SelectField('Type', choices=[('scale', 'Scale (1-10)'), ('yesno', 'Yes/No')], validators=[DataRequired()], default='scale')
    submit = SubmitField('Add Question')

class AnswerForm(FlaskForm):
    answer = RadioField('Your Answer', choices=[(str(i), str(i)) for i in range(11)], validators=[DataRequired()])
    submit = SubmitField('Next')

class CompatibilityForm(FlaskForm):
    user1_id = IntegerField('User 1 ID', validators=[DataRequired()])
    user2_id = IntegerField('User 2 ID', validators=[DataRequired()])
    show_details = SubmitField('Show Details')
    submit = SubmitField('Check Compatibility')

class CompatibilityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, nullable=False)
    user2_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('Database tables created.')
    # Create initial admin user if not exists
    admin_username = 'admin'
    admin_password = 'admin123'  # Change after first login
    if not User.query.filter_by(username=admin_username).first():
        hashed_pw = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin = User(username=admin_username, password_hash=hashed_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print(f'Admin user created: {admin_username} / {admin_password}')
    else:
        print('Admin user already exists.')

@app.cli.command('delete-all-questions')
def delete_all_questions():
    num_deleted = Question.query.delete()
    db.session.commit()
    print(f'Deleted {num_deleted} questions from the database.')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/questions', methods=['GET', 'POST'])
@login_required
def admin_questions():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    form = QuestionForm()
    if form.validate_on_submit():
        q = Question(text=form.text.data, category=form.category.data, type=form.type.data)
        db.session.add(q)
        db.session.commit()
        flash('Question added.', 'success')
        return redirect(url_for('admin_questions'))
    questions = Question.query.all()
    csrf_token = generate_csrf()
    return render_template('admin_questions.html', form=form, questions=questions, csrf_token=csrf_token)

@app.route('/admin/questions/delete/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    q = Question.query.get_or_404(question_id)
    db.session.delete(q)
    db.session.commit()
    flash('Question deleted.', 'info')
    return redirect(url_for('admin_questions'))

@app.route('/questions', methods=['GET', 'POST'])
@login_required
def answer_questions():
    answered_ids = {r.question_id for r in current_user.responses}
    q = Question.query.filter(~Question.id.in_(answered_ids)).first()
    if not q:
        questions = Question.query.all()
        user_answers = {r.question_id: r.answer for r in current_user.responses}
        return render_template('review_answers.html', questions=questions, user_answers=user_answers)
    # Choose form options based on question type
    if q.type == 'yesno':
        choices = [('10', 'Yes'), ('1', 'No')]
    else:
        choices = [(str(i), str(i)) for i in range(1, 11)]
    form = AnswerForm()
    form.answer.choices = choices
    if form.validate_on_submit():
        resp = Response(user_id=current_user.id, question_id=q.id, answer=int(form.answer.data))
        db.session.add(resp)
        db.session.commit()
        return redirect(url_for('answer_questions'))
    return render_template('answer_question.html', form=form, question=q, editing=False)

@app.route('/questions/edit/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_answer(question_id):
    q = Question.query.get_or_404(question_id)
    resp = Response.query.filter_by(user_id=current_user.id, question_id=question_id).first()
    if not resp:
        abort(404)
    if q.type == 'yesno':
        choices = [('10', 'Yes'), ('1', 'No')]
    else:
        choices = [(str(i), str(i)) for i in range(1, 11)]
    form = AnswerForm(answer=str(resp.answer))
    form.answer.choices = choices
    if form.validate_on_submit():
        resp.answer = int(form.answer.data)
        db.session.commit()
        return redirect(url_for('answer_questions'))
    return render_template('answer_question.html', form=form, question=q, editing=True)

@app.route('/admin/stats')
@login_required
def admin_stats():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    user_count = User.query.count()
    users = User.query.all()
    questions = Question.query.count()
    answers_per_user = {u.username: len(u.responses) for u in users}
    total_checks = CompatibilityLog.query.count()
    return render_template('admin_stats.html', user_count=user_count, questions=questions, answers_per_user=answers_per_user, total_checks=total_checks)

@app.route('/compatibility', methods=['GET', 'POST'])
@login_required
def compatibility():
    form = CompatibilityForm()
    result = None
    details = None
    if form.validate_on_submit():
        user1 = User.query.get(form.user1_id.data)
        user2 = User.query.get(form.user2_id.data)
        if not user1 or not user2:
            flash('Invalid user IDs.', 'danger')
        else:
            # Log the compatibility check
            log = CompatibilityLog(user1_id=user1.id, user2_id=user2.id)
            db.session.add(log)
            db.session.commit()
            qids = [q.id for q in Question.query.all()]
            user1_answers = {r.question_id: r.answer for r in user1.responses if r.question_id in qids}
            user2_answers = {r.question_id: r.answer for r in user2.responses if r.question_id in qids}
            total_score = 0
            total_questions = 0
            cat_scores = {}
            cat_counts = {}
            details = []
            for q in Question.query.all():
                if q.id in user1_answers and q.id in user2_answers:
                    diff = abs(user1_answers[q.id] - user2_answers[q.id])
                    score = (10 - diff) / 10
                    total_score += score
                    total_questions += 1
                    if q.category not in cat_scores:
                        cat_scores[q.category] = 0
                        cat_counts[q.category] = 0
                    cat_scores[q.category] += score
                    cat_counts[q.category] += 1
                    details.append({
                        'question': q.text,
                        'category': q.category,
                        'user1_answer': user1_answers[q.id],
                        'user2_answer': user2_answers[q.id],
                        'score': round(score, 2)
                    })
            overall = int((total_score / total_questions) * 100) if total_questions else 0
            cat_percent = {cat: int((cat_scores[cat] / cat_counts[cat]) * 100) if cat_counts[cat] else 0 for cat in cat_scores}
            result = {'score': overall, 'cat_scores': cat_percent, 'total': total_questions}
            if not form.show_details.data:
                details = None
    return render_template('compatibility.html', form=form, result=result, details=details)

if __name__ == '__main__':
    app.run(debug=True) 