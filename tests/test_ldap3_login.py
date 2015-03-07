import unittest
import flask.ext.ldap3_login as ldap3_login
import flask 
from unittest import mock
import ldap3
import logging

log = logging.getLogger(__name__)

DIRECTORY = {
    'dc=com': {
        'dc=mydomain': {
            'ou=users': {
                'cn=Nick Whyte': {
                    'cn': ['Nick Whyte'],
                    'mail': ['nick@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['Whyte'],
                    'givenName': ['Nick'],
                    'objectClass': ['inetOrgPerson'],
                },
                'cn=Fake User': {
                    'cn': ['Fake User'],
                    'mail': ['fake@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['User'],
                    'givenName': ['Fake'],
                    'objectClass': ['inetOrgPerson']
                },
            },
            'ou=groups': {
                'cn=Staff': {
                    'cn': ['Staff'],
                    'description': ['A Group for staff'],
                    'uniqueMember': [
                        'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                        'cn=Fake User,ou=users,dc=mydomain,dc=com',
                    ],
                    'objectClass': ['groupOfUniqueNames']
                },
                'cn=Admins': {
                    'cn': ['Admins'],
                    'description': ['A Group for Admins'],
                    'uniqueMember': [
                        'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                    ],
                    'objectClass': ['groupOfUniqueNames']
                },
            }
        }
    }
}

def get_directory_base_recurse(location, directory):
    if location[0] not in directory:
        return None
    item = directory[location[0]]
    if len(location) == 1:
        return item
    return get_directory_base_recurse(location[1:], item)

def get_directory_base(dn):
    location = list(reversed(dn.split(',')))
    return get_directory_base_recurse(location, directory=DIRECTORY)


class Server(mock.MagicMock):
    pass
class Connection(mock.MagicMock):
    def __init__(self, **kwargs):
        mock.MagicMock.__init__(self)
        self._response = []
        self._result = None
        pass

    def bind(self):
        pass

    def search(self, search_base='', search_filter='(objectClass=*)', search_scope=ldap3.SUBTREE, attributes=None):
        log.info("Search began for base '{}' with filter '{}' in scope '{}' with attributes '{}'".format(
            search_base, search_filter, search_scope, attributes
        ))

        scoped_directory = get_directory_base(search_base)

        if search_scope == ldap3.SUBTREE:
            print("SEARCHING SUBTRE")
        elif search_scope == ldap3.LEVEL:
            # Find object on this level only.
            pass


        elif search_scope == ldap3.BASE:
            print("GET THE BASE OBJECT THING")

        pass

    @property
    def response(self):
        return self._response

    @property
    def result(self):
        return self._result

class ServerPool(mock.MagicMock):
    pass


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

        app.config['LDAP_USER_RDN_ATTR'] = 'uid'
        app.config['LDAP_USER_LOGIN_ATTR'] = 'mail'

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
        r = self.manager.authenticate('myfakeuser', 'lel')
        print(r.status == ldap3_login.AuthenticationResponseStatus.success)


