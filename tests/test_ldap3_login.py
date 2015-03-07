import unittest
import flask.ext.ldap3_login as ldap3_login
import flask 
from unittest import mock

import logging
log = logging.getLogger(__name__)

from Directory import DIRECTORY, get_directory_base
from MockTypes import Server, Connection, ServerPool


@mock.patch('ldap3.ServerPool', new=ServerPool)
@mock.patch('ldap3.Server', new=Server)
@mock.patch('ldap3.Connection', new=Connection)
class BasicTestCase(unittest.TestCase):

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
        app.config['LDAP_USER_SEARCH_SCOPE'] = 'SUBTREE'

        ldap3_manager = ldap3_login.LDAP3LoginManager(app)
        self.manager = ldap3_manager

        @ldap3_manager.save_user
        def save_user(dn, username, data, memberships):
            # print(dn)
            # print(username)
            # print(data)
            # print(memberships)
            pass
        pass

    def tearDown(self):
        pass

    def test_basic(self):
        r = self.manager.authenticate('fake@nickwhyte.com', 'fake123')
        print(r.status == ldap3_login.AuthenticationResponseStatus.success)


