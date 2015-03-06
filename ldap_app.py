from flask import Flask, url_for
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager, login_user, UserMixin, current_user
from flask import render_template_string, redirect
from flask.ext.ldap3_login.forms import LDAPLoginForm

app = Flask(__name__)
# Obviously change these for your own LDAP setup.
app.config['LDAP_HOST'] = 'ldap://127.0.01.'
app.config['LDAP_USER_DN'] = 'cn=users'
app.config['LDAP_GROUP_DN'] = 'ou=groups'
app.config['LDAP_BASE_DN'] = 'dc=mydomain,dc=com'
app.config['LDAP_USER_RDN_ATTR'] = 'cn'
app.config['LDAP_USER_LOGIN_ATTR'] = 'mail'
app.config['SECRET_KEY'] = 'secret'
app.config['DEBUG'] = True

login_manager = LoginManager(app)
ldap_manager = LDAP3LoginManager(app)

# Just store the users in memory
import hashlib
users = {}

class User(UserMixin):
    def __init__(self, dn, username, data):
        self.dn = dn
        self.username = username
        self.data = data

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

    def is_anonymous(self):
        return False

@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    user = User(dn, username, data)
    users[dn] = user
    return user

@app.route('/')
def home():
    if not current_user or current_user.is_anonymous():
        return redirect(url_for('login'))

    template = """
    <h1>Welcome: {{ current_user.data.cn }}</h1>
    <h2>{{ current_user.dn }}</h2>
    """

    return render_template_string(template)

@app.route('/login', methods=['GET','POST'])
def login():
    template = """
    {{ get_flashed_messages() }}
    {{ form.errors }}
    <form method="POST">
        <label>Username{{ form.username() }}</label>
        <label>Password{{ form.password() }}</label>
        {{ form.submit() }}
        {{ form.hidden_tag() }}
    </form>
    """

    form = LDAPLoginForm()

    if form.validate_on_submit():
        login_user(form.user)
        return redirect('/')

    return render_template_string(template, form=form)

if __name__ == '__main__':
    app.run()