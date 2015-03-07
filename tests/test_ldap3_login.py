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
            'cn=Bind': {
                'cn': ['BIND'],
                'mail': ['bind@localhost.com'],
                'objectclass': ['inetOrgPerson'],
                'dn': 'cn=Bind,dc=mydomain,dc=com',
                'password': 'bind123'
            },
            'ou=users': {
                'cn=Nick Whyte': {
                    'cn': ['Nick Whyte'],
                    'mail': ['nick@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['Whyte'],
                    'givenname': ['Nick'],
                    'objectclass': ['inetOrgPerson'],
                    'dn': 'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                    'password': 'fake123'
                },
                'cn=Fake User': {
                    'cn': ['Fake User'],
                    'mail': ['fake@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['User'],
                    'givenname': ['Fake'],
                    'objectclass': ['inetOrgPerson'],
                    'dn': 'cn=Fake User,ou=users,dc=mydomain,dc=com',
                    'password': 'fake123'
                },

            },
            'ou=groups': {
                'cn=Staff': {
                    'cn': ['Staff'],
                    'description': ['A Group for staff'],
                    'uniquemember': [
                        'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                        'cn=Fake User,ou=users,dc=mydomain,dc=com',
                    ],
                    'objectclass': ['groupOfUniqueNames'],
                    'dn': 'cn=Staff,ou=groups,dc=mydomain,dc=com',
                },
                'cn=Admins': {
                    'cn': ['Admins'],
                    'description': ['A Group for Admins'],
                    'uniquemember': [
                        'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                    ],
                    'objectclass': ['groupOfUniqueNames'],
                    'dn': 'cn=Admins,ou=groups,dc=mydomain,dc=com',
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

import re
single_filter = re.compile(r'([A-Za-z0-9_\-]+)=(.+)')

def and_(cmps, data):
    return all([comp(data) for comp in cmps])

def or_(cmps, data):
    return any([comp(data) for comp in cmps])


def build_comparison(cmp_string):
    stop = len(cmp_string)
    if cmp_string[0] == '(':
        depth = last_depth = i = 0
        cmps = []


        while i < len(cmp_string):
            if cmp_string[i] == '(':
                depth += 1
                if depth == 1:
                    last_pop = i+1

            elif cmp_string[i] == ')':
                depth -= 1

            if depth == 0 and last_depth == 1:
                cmps.append(build_comparison(cmp_string[last_pop:i]))
            
            last_depth = depth
            i+=1
        return cmps
                

    elif cmp_string[0] == '&':
        cmps = build_comparison(cmp_string[1:])
        return lambda data: and_(cmps, data)


    elif cmp_string[0] == '|':
        cmps = build_comparison(cmp_string[1:])
        return lambda data: or_(cmps, data)

    else:
        match = single_filter.match(cmp_string)
        if match:
            field, value = match.group(1, 2)

            return lambda data: type(data) == dict and  value in data[field]
        else:
            raise Exception("Malformed Filter '{0}'".format(cmp_string))


class Server(mock.MagicMock):
    pass
class Connection(mock.MagicMock):
    def __init__(self, user=None, password=None, **kwargs):
        mock.MagicMock.__init__(self)
        self._response = []
        self._result = None
        self.user = user
        self.password = password
        pass

    def bind(self):
        if self.user:
            # Validate the bind user.
            bind_user = get_directory_base(self.user)
            if self.password == bind_user['password']:
                return True

            raise ldap3.LDAPInvalidCredentialsResult
        else:
            return True

    def search(self, search_base='', search_filter='(objectClass=*)', search_scope=ldap3.SUBTREE, attributes=None):
        log.info("Search began for base '{}' with filter '{}' in scope '{}' with attributes '{}'".format(
            search_base, search_filter, search_scope, attributes
        ))

        check_user = build_comparison(search_filter)[0]

        scoped_directory = get_directory_base(search_base)

        if search_scope == ldap3.SUBTREE:
            # Perform a recursive search strategy

            def recurse_search(dictionary):
                items = []
                for item in dictionary.values():
                    if check_user(item):
                        items.append(item)

                    if type(item) == dict:
                        items.extend(recurse_search(item))

                return items

            items = recurse_search(scoped_directory)
            items = [dict(attributes=user, dn=user['dn']) for user in items]
            self._result = len(items) > 0
            self._response = items


        elif search_scope == ldap3.LEVEL:
            
            matching = [dict(attributes=user, dn=user['dn']) for user in scoped_directory.values() if check_user(user)]
            self._result = len(matching) > 0
            self._response = matching

        elif search_scope == ldap3.BASE:
            result = check_user(scoped_directory)
            self._result = result
            if self._result:
                self._response = [scoped_directory]
            else:
                self._response = []

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


