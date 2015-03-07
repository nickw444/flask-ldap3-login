import unittest
import flask.ext.ldap3_login as ldap3_login
import flask 
import mock

import logging
log = logging.getLogger(__name__)

from Directory import DIRECTORY, get_directory_base
from MockTypes import Server, Connection, ServerPool

from flask.ext.ldap3_login.forms import LDAPLoginForm

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.config['LDAP_HOST'] = 'ad.mydomain.com'
        app.config['LDAP_BASE_DN'] = 'dc=mydomain,dc=com'
        app.config['LDAP_USER_DN'] = 'ou=users'
        app.config['LDAP_GROUP_DN'] = 'ou=groups'
        app.config['LDAP_BIND_USER_DN'] = 'cn=Bind,dc=mydomain,dc=com'
        app.config['LDAP_BIND_USER_PASSWORD'] = 'bind123'
        app.config['LDAP_USER_RDN_ATTR'] = 'uid'
        app.config['LDAP_USER_LOGIN_ATTR'] = 'mail'
        app.config['SECRET_KEY'] = 'secrets'
        app.config['WTF_CSRF_ENABLED'] = False

        self.app = app
        ldap3_manager = ldap3_login.LDAP3LoginManager(app)
        self.manager = ldap3_manager

        pass

    def tearDown(self):
        pass

@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class AuthenticateDirectTestCase(BaseTestCase):
    def setUp(self):
        super(AuthenticateDirectTestCase, self).setUp()

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR':'cn',
            'LDAP_USER_LOGIN_ATTR':'cn',
        })


    def tearDown(self):
        super(AuthenticateDirectTestCase, self).tearDown()

    def test_login(self):
        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.assertEqual(r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('Nick Whyte', 'fake1234')
        self.assertEqual(r.status, ldap3_login.AuthenticationResponseStatus.fail)

    def test_save_user(self):
        users = {}
        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return users[dn]

        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.manager._save_user(
            r.user_dn,
            r.user_id,
            r.user_info,
            r.user_groups
        )
        self.assertIn(r.user_dn, users)

    def test_save_user_in_form(self):
        users = {}

        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return data

        with self.app.test_request_context():
            form = LDAPLoginForm(username='Nick Whyte', password='fake123')
            self.assertTrue(form.validate())
            self.assertIn(form.user['dn'], users)

@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class AuthenticateSearchTestCase(BaseTestCase):
    def setUp(self):
        super(AuthenticateSearchTestCase, self).setUp()

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR':'cn',
            'LDAP_USER_LOGIN_ATTR':'mail',
        })

    def tearDown(self):
        super(AuthenticateSearchTestCase, self).tearDown()

    def test_login(self):
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake123')
        self.assertEqual(r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake1234')
        self.assertEqual(r.status, ldap3_login.AuthenticationResponseStatus.fail)

    def test_save_user(self):

        users = {}

        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return users[dn]

        r = self.manager.authenticate('nick@nickwhyte.com', 'fake123')
        self.manager._save_user(
            r.user_dn,
            r.user_id,
            r.user_info,
            r.user_groups
        )
        self.assertIn(r.user_dn, users)

    def test_save_user_in_form(self):
        users = {}

        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return users[dn] 

        with self.app.test_request_context():
            form = LDAPLoginForm(username='nick@nickwhyte.com', password='fake123')
            self.assertTrue(form.validate())
            self.assertIn(form.user['dn'], users)

@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class GroupMembershipTestCase(BaseTestCase):
    def setUp(self):
        super(GroupMembershipTestCase, self).setUp()

    def tearDown(self):
        super(GroupMembershipTestCase, self).tearDown()

    def test_group_membership(self):
        groups = self.manager.get_user_groups(dn='cn=Nick Whyte,ou=users,dc=mydomain,dc=com')
        self.assertIn(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Staff'], groups)
        self.assertIn(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Admins'], groups)

        groups = self.manager.get_user_groups(dn='cn=Fake User,ou=users,dc=mydomain,dc=com')
        self.assertIn(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Staff'], groups)
        self.assertNotIn(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Admins'], groups)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class GroupExistsTestCase(BaseTestCase):
    def setUp(self):
        super(GroupExistsTestCase, self).setUp()

    def tearDown(self):
        super(GroupExistsTestCase, self).tearDown()

    def test_group_exists(self):
        group = self.manager.get_group_info(dn='cn=Staff,ou=groups,dc=mydomain,dc=com')
        self.assertEqual(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Staff'], group)
        group = self.manager.get_group_info(dn='cn=Admins,ou=groups,dc=mydomain,dc=com')
        self.assertEqual(DIRECTORY['dc=com']['dc=mydomain']['ou=groups']['cn=Admins'], group)

@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class SessionContextTextCase(BaseTestCase):
    def test_context_push(self):
        with self.app.test_request_context():
            connection = self.manager.connection
            self.assertTrue(hasattr(stack.top, 'ldap3_manager_main_connection'))

        with self.app.test_request_context():
            # Get a new context
            self.assertFalse(hasattr(stack.top, 'ldap3_manager_main_connection'))

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AuthenticateDirectTestCase))
    suite.addTest(unittest.makeSuite(AuthenticateSearchTestCase))
    suite.addTest(unittest.makeSuite(GroupMembershipTestCase))
    suite.addTest(unittest.makeSuite(GroupExistsTestCase))
    suite.addTest(unittest.makeSuite(SessionContextTextCase))
    return suite
