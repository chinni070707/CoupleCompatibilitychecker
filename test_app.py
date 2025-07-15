import pytest
from app import app, db, User, Question, Response, CompatibilityLog, bcrypt
from flask_login import login_user
import random
import json

@pytest.fixture(scope='module')
def app_fixture():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_database.db'
    app.config['WTF_CSRF_ENABLED'] = False # Explicitly disable CSRF for testing

    # Push a context for setup
    with app.app_context():
        db.create_all()

        # Create a test admin user for adding questions
        if not User.query.filter_by(username='testadmin').first():
            hashed_pw = bcrypt.generate_password_hash('testadminpass').decode('utf-8')
            admin_user = User(username='testadmin', password_hash=hashed_pw, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()
        
        # Create test users directly in the database for consistency
        if not User.query.filter_by(username='testuser1').first():
            hashed_pw1 = bcrypt.generate_password_hash('password123').decode('utf-8')
            user1 = User(username='testuser1', password_hash=hashed_pw1)
            db.session.add(user1)

        if not User.query.filter_by(username='testuser2').first():
            hashed_pw2 = bcrypt.generate_password_hash('password123').decode('utf-8')
            user2 = User(username='testuser2', password_hash=hashed_pw2)
            db.session.add(user2)
        db.session.commit() # Commit new users

        # Import questions from questions.json for testing
        try:
            with open('templates/questions.json', 'r') as f:
                questions_data = json.load(f)
                for category_data in questions_data:
                    category_name = category_data.get('category')
                    for q_data in category_data.get('questions', []):
                        question_type_map = {
                            'yes_no': 'yesno',
                            'scale': 'scale'
                        }
                        question_type = question_type_map.get(q_data.get('question_type'), 'scale')
                        if all(key in q_data for key in ['text']):
                            q = Question(text=q_data['text'], category=category_name, type=question_type)
                            db.session.add(q)
                db.session.commit()
        except FileNotFoundError:
            print("templates/questions.json not found. Please ensure it exists for tests.")
        except Exception as e:
            print(f"Error importing questions for test setup: {e}")

    # Yield the app instance itself. This app instance will be used by tests.
    yield app

    # Teardown logic (runs after all tests in the module have completed)
    with app.app_context():
        # db.drop_all()


def login_test_user(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)


def register_test_user(client, username, password):
    # This function is now mostly for completeness, as users are pre-created by the fixture.
    # It can still be used for scenarios where registration within a test is needed, but for
    # these tests, users are pre-provisioned.
    return client.post('/register', data=dict(
        username=username,
        password=password,
        confirm_password=password
    ), follow_redirects=True)


def test_user_registration_and_login(app_fixture):
    with app_fixture.app_context(): # Use the app instance from the fixture
        client = app_fixture.test_client() # Get the test client within this context
        # Test login for User 1 (already created by fixture)
        login_response1 = login_test_user(client, 'testuser1', 'password123')
        assert f"Welcome, testuser1!" in login_response1.get_data(as_text=True)

        # Test login for User 2 (already created by fixture)
        login_response2 = login_test_user(client, 'testuser2', 'password123')
        assert f"Welcome, testuser2!" in login_response2.get_data(as_text=True)


def test_user_answers_questions_and_compatibility_check(app_fixture):
    with app_fixture.app_context(): # Use the app instance from the fixture
        client = app_fixture.test_client() # Get the test client within this context

        # Retrieve pre-created users
        user1 = User.query.filter_by(username='testuser1').first()
        user2 = User.query.filter_by(username='testuser2').first()
        assert user1 is not None # Ensure user1 exists
        assert user2 is not None # Ensure user2 exists
        
        # Login User 1 to answer questions
        login_test_user(client, 'testuser1', 'password123')
        questions = Question.query.all()
        for q in questions:
            answer = random.randint(1, 10) if q.type == 'scale' else random.choice([1, 10]) # 1 for No, 10 for Yes
            client.post('/questions', data=dict(
                answer=str(answer)
            ), follow_redirects=True)
        
        # Logout User 1
        client.get('/logout', follow_redirects=True)

        # Login User 2 to answer questions
        login_test_user(client, 'testuser2', 'password123')
        for q in questions:
            answer = random.randint(1, 10) if q.type == 'scale' else random.choice([1, 10])
            client.post('/questions', data=dict(
                answer=str(answer)
            ), follow_redirects=True)
        
        # Logout User 2
        client.get('/logout', follow_redirects=True)

        # Now, perform compatibility check
        # Login as one of the users or admin to perform the check
        login_test_user(client, 'testuser1', 'password123') # User1 logs in to check compatibility
        
        compatibility_response = client.post('/compatibility', data=dict(
            user1_id=user1.username, # Use username now
            user2_id=user2.username, # Use username now
            submit='Check Compatibility'
        ), follow_redirects=True)

        assert b"Overall Match Score" in compatibility_response.data
        assert CompatibilityLog.query.filter_by(user1_username=user1.username, user2_username=user2.username).count() == 1
        
        # Test "Show Details" button as well
        compatibility_response_details = client.post('/compatibility', data=dict(
            user1_id=user1.username,
            user2_id=user2.username,
            show_details='Show Details'
        ), follow_redirects=True)
        assert b"Per-Question Details" in compatibility_response_details.data
        assert CompatibilityLog.query.filter_by(user1_username=user1.username, user2_username=user2.username).count() == 2 # Check increased log count

