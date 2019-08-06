import ldap3

class Ldap3AppState:
    def __init__(self):
        pass


class LDAP3LoginManager:
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault('LDAP_PORT', 389)
        app.config.setdefault('LDAP_HOST', None)
        app.config.setdefault('LDAP_USE_SSL', False)
        app.config.setdefault('LDAP_READONLY', True)
        app.config.setdefault('LDAP_CHECK_NAMES', True)
        app.config.setdefault('LDAP_BIND_DIRECT_CREDENTIALS', False)
        app.config.setdefault('LDAP_BIND_DIRECT_PREFIX', '')
        app.config.setdefault('LDAP_BIND_DIRECT_SUFFIX', '')
        app.config.setdefault('LDAP_BIND_DIRECT_GET_USER_INFO', True)
        app.config.setdefault('LDAP_ALWAYS_SEARCH_BIND', False)
        app.config.setdefault('LDAP_BASE_DN', '')
        app.config.setdefault('LDAP_BIND_USER_DN', None)
        app.config.setdefault('LDAP_BIND_USER_PASSWORD', None)
        app.config.setdefault('LDAP_SEARCH_FOR_GROUPS', True)
        app.config.setdefault('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND', False)

        # Prepended to the Base DN to limit scope when searching for
        # Users/Groups.
        app.config.setdefault('LDAP_USER_DN', '')
        app.config.setdefault('LDAP_GROUP_DN', '')

        app.config.setdefault('LDAP_BIND_AUTHENTICATION_TYPE', 'SIMPLE')

        # Ldap Filters
        app.config.setdefault('LDAP_USER_SEARCH_SCOPE',
                               'LEVEL')
        app.config.setdefault('LDAP_USER_OBJECT_FILTER',
                               '(objectclass=person)')
        app.config.setdefault('LDAP_USER_LOGIN_ATTR', 'uid')
        app.config.setdefault('LDAP_USER_RDN_ATTR', 'uid')
        app.config.setdefault(
            'LDAP_GET_USER_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)

        app.config.setdefault('LDAP_GROUP_SEARCH_SCOPE',
                               'LEVEL')
        app.config.setdefault(
            'LDAP_GROUP_OBJECT_FILTER', '(objectclass=group)')
        app.config.setdefault('LDAP_GROUP_MEMBERS_ATTR', 'uniqueMember')
        app.config.setdefault(
            'LDAP_GET_GROUP_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)
        app.config.setdefault('LDAP_ADD_SERVER', True)

        if app.config['LDAP_ADD_SERVER']:
            self.add_server(
                hostname=app.config['LDAP_HOST'],
                port=app.config['LDAP_PORT'],
                use_ssl=app.config['LDAP_USE_SSL']
            )
