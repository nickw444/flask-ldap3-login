import unittest
import flask_ldap3_login as ldap3_login
import flask
import mock
from flask import abort
import logging
from ldap3 import Tls

from .Directory import DIRECTORY
from .MockTypes import Server, Connection, ServerPool

from flask_ldap3_login.forms import LDAPLoginForm

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

log = logging.getLogger(__name__)


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
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'cn',
        })

    def tearDown(self):
        super(AuthenticateDirectTestCase, self).tearDown()

    def test_login(self):
        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('Nick Whyte', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)

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
        assert r.user_dn in users

    def test_save_user_in_form(self):
        users = {}

        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return data

        with self.app.test_request_context():
            form = LDAPLoginForm(username='Nick Whyte', password='fake123')
            self.assertTrue(form.validate())
            assert form.user['dn'] in users


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class DirectBindPrefixSuffixTestCase(BaseTestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.config['LDAP_HOST'] = 'ad2.mydomain.com'
        app.config['LDAP_BASE_DN'] = 'dc=mydomain,dc=com'
        app.config['LDAP_USER_DN'] = 'ou=users'
        app.config['LDAP_GROUP_DN'] = 'ou=groups'
        app.config['LDAP_BIND_USER_DN'] = 'cn=Bind,dc=mydomain,dc=com'
        app.config['LDAP_BIND_DIRECT_PREFIX'] = 'Prefix'
        app.config['LDAP_BIND_DIRECT_SUFFIX'] = ''
        app.config['LDAP_BIND_USER_PASSWORD'] = 'bind123'
        app.config['LDAP_USER_RDN_ATTR'] = 'uid'
        app.config['LDAP_USER_LOGIN_ATTR'] = 'mail'
        app.config['SECRET_KEY'] = 'secrets'
        app.config['WTF_CSRF_ENABLED'] = False

        self.app = app
        ldap3_manager = ldap3_login.LDAP3LoginManager(app)
        self.manager = ldap3_manager

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'cn',
            'LDAP_HOST': 'ad2.mydomain.com',
        })

    def test_login(self):
        r = self.manager.authenticate('Fake User', 'fake321')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('Fake User', 'fake3210')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class EmptyUserGroupDNTestCase(BaseTestCase):
    def setUp(self):
        super(EmptyUserGroupDNTestCase, self).setUp()

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'cn',
            'LDAP_BASE_DN': 'ou=users,dc=mydomain,dc=com',
            'LDAP_USER_DN': '',
            'LDAP_GROUP_DN': '',
        })

    def test_login(self):
        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('Nick Whyte', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class NoFlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        config = dict(
            LDAP_HOST='ad.mydomain.com',
            LDAP_BASE_DN='dc=mydomain,dc=com',
            LDAP_USER_DN='ou=users',
            LDAP_GROUP_DN='ou=groups',
            LDAP_BIND_USER_DN='cn=Bind,dc=mydomain,dc=com',
            LDAP_BIND_USER_PASSWORD='bind123',
            LDAP_USER_RDN_ATTR='cn',
            LDAP_USER_LOGIN_ATTR='cn'
        )
        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(config)
        self.manager = ldap3_manager

    def test_login(self):
        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('Nick Whyte', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)

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
        assert r.user_dn in users

    def test_connection_outside_of_flask(self):
        exception_raised = False
        try:
            self.manager.connection
        except Exception:
            exception_raised = True

        self.assertTrue(exception_raised)

    def test_make_connection(self):
        connection = self.manager.make_connection(
            'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
            'fake123'
        )
        connection.bind()
        connection.unbind()


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class BadServerAddressTestCase(BaseTestCase):
    def setUp(self):
        app = flask.Flask(__name__)
        app.config['LDAP_HOST'] = 'ad2.mydomain.com'
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

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'cn',
            'LDAP_HOST': 'ad2.mydomain.com',
        })

    def test_direct_bind_with_bad_server(self):
        r = self.manager.authenticate('Nick Whyte', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)
        r = self.manager.authenticate('Nick Whyte', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)

    def test_search_bind_with_bad_server(self):
        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'mail',
            'LDAP_HOST': 'ad2.mydomain.com',
        })
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class AuthenticateSearchTestCase(BaseTestCase):
    def setUp(self):
        super(AuthenticateSearchTestCase, self).setUp()

        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'mail',
        })

    def tearDown(self):
        super(AuthenticateSearchTestCase, self).tearDown()

    def test_login(self):
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('nick@nickwhyte.com', 'fake1234')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)

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
        assert r.user_dn in users

    def test_save_user_in_form(self):
        users = {}

        @self.manager.save_user
        def user_saver(dn, username, data, memberships):
            users[dn] = data
            return users[dn]

        with self.app.test_request_context():
            form = LDAPLoginForm(
                username='nick@nickwhyte.com', password='fake123')
            self.assertTrue(form.validate())
            assert form.user['dn'] in users

            form = LDAPLoginForm(
                username='nick@nickwhyte.com', password='fake1234')
            self.assertFalse(form.validate())


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class LDAPLoginFormTestCase(BaseTestCase):
    def test_invalid_form_data(self):
        with self.app.test_request_context():
            form = LDAPLoginForm(password='fake1234')
            self.assertFalse(form.validate())

    def test_with_valid_form_data_invalid_ldap(self):
        with self.app.test_request_context():
            form = LDAPLoginForm(
                username='nick@nickwhyte.com', password='fake1234')
            self.assertFalse(form.validate())


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class FailOnMultipleFoundTestCase(BaseTestCase):

    def test_ambiguious_login_field(self):
        self.manager.config.update({
            'LDAP_USER_RDN_ATTR': 'cn',
            'LDAP_USER_LOGIN_ATTR': 'objectclass',
        })

        r = self.manager.authenticate('person', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)
        r = self.manager.authenticate('person', 'fake321')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.success)

        self.manager.config.update({
            'LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND': True
        })
        r = self.manager.authenticate('person', 'fake123')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)
        r = self.manager.authenticate('person', 'fake321')
        self.assertEqual(
            r.status, ldap3_login.AuthenticationResponseStatus.fail)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class GroupMembershipTestCase(BaseTestCase):
    def setUp(self):
        super(GroupMembershipTestCase, self).setUp()

    def tearDown(self):
        super(GroupMembershipTestCase, self).tearDown()

    def test_group_membership(self):
        groups = self.manager.get_user_groups(
            dn='cn=Nick Whyte,ou=users,dc=mydomain,dc=com')

        assert DIRECTORY['dc=com']['dc=mydomain'][
            'ou=groups']['cn=Staff'] in groups
        assert DIRECTORY['dc=com']['dc=mydomain'][
            'ou=groups']['cn=Admins'] in groups

        groups = self.manager.get_user_groups(
            dn='cn=Fake User,ou=users,dc=mydomain,dc=com')
        assert DIRECTORY['dc=com']['dc=mydomain'][
            'ou=groups']['cn=Staff'] in groups
        assert DIRECTORY['dc=com']['dc=mydomain'][
            'ou=groups']['cn=Admins'] not in groups


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class GetUserInfoTestCase(BaseTestCase):

    def test_get_user_info_for_username(self):
        user = self.manager.get_user_info_for_username(
            'nick@nickwhyte.com'
        )
        self.assertEqual(user, DIRECTORY['dc=com']['dc=mydomain'][
                         'ou=users']['cn=Nick Whyte'])


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class GroupExistsTestCase(BaseTestCase):
    def setUp(self):
        super(GroupExistsTestCase, self).setUp()

    def tearDown(self):
        super(GroupExistsTestCase, self).tearDown()

    def test_group_exists(self):
        group = self.manager.get_group_info(
            dn='cn=Staff,ou=groups,dc=mydomain,dc=com')
        self.assertEqual(DIRECTORY['dc=com']['dc=mydomain'][
                         'ou=groups']['cn=Staff'], group)
        group = self.manager.get_group_info(
            dn='cn=Admins,ou=groups,dc=mydomain,dc=com')
        self.assertEqual(DIRECTORY['dc=com']['dc=mydomain'][
                         'ou=groups']['cn=Admins'], group)


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class SessionContextTextCase(BaseTestCase):
    def test_context_push(self):
        with self.app.test_request_context():
            connection = self.manager.connection
            self.assertTrue(
                hasattr(stack.top, 'ldap3_manager_main_connection'))
            connection2 = self.manager.connection

            self.assertEqual(connection, connection2)

        with self.app.test_request_context():
            # Get a new context
            self.assertFalse(
                hasattr(stack.top, 'ldap3_manager_main_connection'))

    def test_context_pop_on_exception(self):
        try:
            with self.app.test_request_context():
                self.manager.connection
                self.manager._make_connection()
                self.assertEqual(len(stack.top.ldap3_manager_connections), 1)
                # Raise an exception so teardown gets done
                abort(404)
        except Exception:
            pass

        with self.app.test_request_context():
            self.assertFalse(
                hasattr(stack.top, 'ldap3_manager_main_connection'))
            self.assertFalse(hasattr(stack.top, 'ldap3_manager_connections'))


class AppFactoryTestCase(BaseTestCase):
    """
    Tests whether the popular Flask app factory pattern can be used.
    """

    def test_server_pool(self):
        """
        To support the app factory pattern, the server pool must be reset when
        init_app is called.
        The test is executed 10 times because if you e.g. run unit tests you
        likely reinitialize the app many times.
        """
        for i in range(10):
            self.manager.init_app(self.app)
            self.assertEqual(len(list(self.manager._server_pool)), 1)


class LDAPAddServerConfigTestCase(unittest.TestCase):
    """Tests for the `LDAP_ADD_SERVER` config key"""

    DEFAULT_CONFIG = dict(
        LDAP_HOST='ad.mydomain.com',
        LDAP_BASE_DN='dc=mydomain,dc=com',
        LDAP_USER_DN='ou=users',
        LDAP_GROUP_DN='ou=groups',
        LDAP_BIND_USER_DN='cn=Bind,dc=mydomain,dc=com',
        LDAP_BIND_USER_PASSWORD='bind123',
        LDAP_USER_RDN_ATTR='cn',
        LDAP_USER_LOGIN_ATTR='cn'
    )

    def test_server_added_when_unset(self):
        """
        Ensures a default server is added when `LDAP_ADD_SERVER` is not set.
        """
        config = dict(LDAPAddServerConfigTestCase.DEFAULT_CONFIG)

        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(config)

        self.assertEqual(len(list(ldap3_manager._server_pool)), 1)

    def test_server_added_when_true(self):
        """
        Ensures a default server is added when `LDAP_ADD_SERVER` is True.
        """
        config = dict(LDAPAddServerConfigTestCase.DEFAULT_CONFIG)
        config['LDAP_ADD_SERVER'] = True

        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(config)

        self.assertEqual(len(list(ldap3_manager._server_pool)), 1)

    def test_server_added_when_false(self):
        """
        Ensures no server is added when `LDAP_ADD_SERVER` is False.
        """
        config = dict(LDAPAddServerConfigTestCase.DEFAULT_CONFIG)
        config['LDAP_ADD_SERVER'] = False

        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(config)

        self.assertEqual(len(list(ldap3_manager._server_pool)), 0)


class AddServerTestCase(unittest.TestCase):
    """
    Tests for the `add_server` method.
    """

    DEFAULT_CONFIG = dict(
        LDAP_HOST='ad.mydomain.com',
        LDAP_BASE_DN='dc=mydomain,dc=com',
        LDAP_USER_DN='ou=users',
        LDAP_GROUP_DN='ou=groups',
        LDAP_BIND_USER_DN='cn=Bind,dc=mydomain,dc=com',
        LDAP_BIND_USER_PASSWORD='bind123',
        LDAP_USER_RDN_ATTR='cn',
        LDAP_USER_LOGIN_ATTR='cn',
        LDAP_ADD_SERVER=False
    )

    def test_error_on_use_ssl_and_tls_ctx(self):
        """
        Ensures a ValueError is thrown when use_ssl is False and a TLS context
        is passed together.
        """
        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(AddServerTestCase.DEFAULT_CONFIG)

        def add_server():
            return ldap3_manager.add_server("ad2.mydomain.com", 389,
                                            use_ssl=False, tls_ctx=object())

        self.assertRaises(ValueError, add_server)

    @mock.patch('ldap3.Server', new=Server)
    @mock.patch('ldap3.ServerPool', new=ServerPool)
    def test_server_with_no_tls_ctx(self):
        """
        Ensures a server is created/added to the pool, however that the server
        was instantiated with `tls=None` and  use_ssl=False
        """
        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(AddServerTestCase.DEFAULT_CONFIG)
        ldap3_manager.add_server("ad2.mydomain.com", 389, use_ssl=False, tls_ctx=None)

        self.assertEqual(len(ldap3_manager._server_pool.servers), 1)

        server = ldap3_manager._server_pool.servers[-1]
        self.assertEqual(server.tls, None)
        self.assertFalse(server.use_ssl)

    @mock.patch('ldap3.Server', new=Server)
    @mock.patch('ldap3.ServerPool', new=ServerPool)
    def test_server_with_no_tls_with_ssl(self):
        """
        Ensures a server is created/added to the pool, however that the server
        was instantiated with `tls=None` and use_ssl=True.
        """
        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(AddServerTestCase.DEFAULT_CONFIG)
        ldap3_manager.add_server("ad2.mydomain.com", 389,
                                 use_ssl=True, tls_ctx=None)

        self.assertEqual(len(ldap3_manager._server_pool.servers), 1)

        server = ldap3_manager._server_pool.servers[-1]
        self.assertEqual(server.tls, None)
        self.assertTrue(server.use_ssl)

    @mock.patch('ldap3.Server', new=Server)
    @mock.patch('ldap3.ServerPool', new=ServerPool)
    def test_server_with_tls_with_ssl(self):
        """
        Ensures a server is created/added to the pool, however that the server
        was instantiated with `tls=<TLS CTX OBJECT>` and use_ssl=True.
        """
        fake_tls_ctx = Tls()

        ldap3_manager = ldap3_login.LDAP3LoginManager()
        ldap3_manager.init_config(AddServerTestCase.DEFAULT_CONFIG)
        ldap3_manager.add_server("ad2.mydomain.com", 389,
                                 use_ssl=True, tls_ctx=fake_tls_ctx)

        self.assertEqual(len(ldap3_manager._server_pool.servers), 1)

        server = ldap3_manager._server_pool.servers[-1]
        self.assertEqual(server.tls, fake_tls_ctx)
        self.assertTrue(server.use_ssl)
