import logging
import flask
import ldap3

log = logging.getLogger(__name__)

class LDAP3ServerConnectionException(Exception):
    pass

from enum import Enum

class AuthenticationResponseStatus(Enum):
    fail = 'fail'
    success = 'success'

class AuthenticationResponse(object):
    status = AuthenticationResponseStatus.fail
    user_info = None
    user_id = None
    user_dn = None


class LDAP3LoginManager(object):
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

        self._save_user = None

    def init_app(self, app):
        '''
        Configures an application. This registers an `after_request` call, and
        attaches this `LoginManager` to it as `app.login_manager`.
        '''

        app.ldap_login_manager = self

        app.config.setdefault('LDAP_PORT', 389)
        app.config.setdefault('LDAP_HOST', None)
        app.config.setdefault('LDAP_USE_SSL', False)
        app.config.setdefault('LDAP_BASE_DN', '')
        app.config.setdefault('LDAP_BIND_USER_DN', None)
        app.config.setdefault('LDAP_BIND_USER_PASSWORD', None)
        
        app.config.setdefault('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND', False)

        # Prepended to the Base DN to limit scope when searching for Users/Groups.
        app.config.setdefault('LDAP_USER_DN', '')
        app.config.setdefault('LDAP_GROUP_DN', '')

        app.config.setdefault('LDAP_USER_SEARCH_SCOPE', 'SEARCH_SCOPE_SINGLE_LEVEL')
        app.config.setdefault('LDAP_GROUP_SEARCH_SCOPE', 'SEARCH_SCOPE_SINGLE_LEVEL')

        # Ldap Filters
        app.config.setdefault('LDAP_USER_OBJECT_FILTER', '(objectclass=inetorgperson)')
        app.config.setdefault('LDAP_USER_LOGIN_ATTR_HUMAN_NAME', 'User ID')
        app.config.setdefault('LDAP_USER_LOGIN_ATTR', 'uid')
        app.config.setdefault('LDAP_GROUP_OBJECT_FILTER', '(objectclass=groupOfUniqueNames)')
        app.config.setdefault('LDAP_GROUP_MEMBERS_ATTR', 'uniqueMember')
        app.config.setdefault('LDAP_USER_MEMBER_ATTR', 'memberOf')
        app.config.setdefault('LDAP_USER_RDN_ATTR', 'uid')
        app.config.setdefault('LDAP_GET_USER_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)
        app.config.setdefault('LDAP_GET_GROUP_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)

        app.config.setdefault('LDAP_BIND_AUTHENTICATION_TYPE', 'AUTH_SIMPLE')


        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown)
        else:
            app.teardown_request(self.teardown)

        self.app = app
        self.config = app.config

        self._server_pool = ldap3.ServerPool(
            [],
            ldap3.POOLING_STRATEGY_FIRST,
            active=True, 
            exhaust=True
        )
        
        self.add_server(
            hostname=self.config.get('LDAP_HOST'),
            port=self.config.get('LDAP_PORT'),
            use_ssl=self.config.get('LDAP_USE_SSL')
        )

    def add_server(self, hostname, port, use_ssl):
        server = ldap3.Server(hostname, port=port, use_ssl=use_ssl)
        self._server_pool.add(server)
        return self._server_pool

    def teardown(self, exception):
        print("TEARDOWN FOR SOMETING?")
        pass


    def save_user(self, callback):
        '''
        This sets the callback for saving a user that has been looked up from from ldap. 
        The function you set should take a user dn (unicode), username (unicode) 
        and userdata (dict).
        :param callback: The callback for retrieving a user object.
        '''

        self._save_user = callback
        return callback


    def authenticate(self, username, password):
        if self.config.get('LDAP_USER_RDN_ATTR') == self.config.get('LDAP_USER_LOGIN_ATTR'):
            # Since the user's RDN is the same as the login field, 
            # we can do a direct bind.
            result = self.authenticate_direct_bind(username, password)
        else:
            # We need to search the User's DN to find who the user is (and their DN)
            # so we can try bind with their password.
            result = self.authenticate_search_bind(username, password)

        if result.status == AuthenticationResponseStatus.success and self._save_user:
            self._save_user(result.user_dn, result.user_id, result.user_info)

        return result


    def authenticate_direct_bind(self, username, password):
        # Format the username for direct binding
        bind_user = '{rdn}={username},{user_search_dn}'.format(
            rdn=self.config.get('LDAP_USER_RDN_ATTR'),
            username=username,
            user_search_dn=self.full_user_search_dn,
        )

        log.debug("Directly binding a connection to a server with user:'{}'".format(bind_user))
        connection = self.make_connection(
            bind_user=bind_user, 
            bind_password=password,
        )

        response = AuthenticationResponse()

        try:
            connection.bind()
            log.debug("Authentication was successful for user '{}'".format(username))
            response.status = AuthenticationResponseStatus.success
            # Get user info here.

            user_info = self.get_user_info(dn=bind_user, _connection=connection)
            response.user_dn = bind_user
            response.user_id = username
            response.user_info = user_info


        except ldap3.LDAPInvalidCredentialsResult as e:
            log.debug("Authentication was not successful for user '{}'".format(username))
            response.status = AuthenticationResponseStatus.fail
        except Exception as e:
            self.destroy_connection(connection)
            log.error(e)
            raise e
        
        return response

    def authenticate_search_bind(self, username, password):
        connection = self.make_connection(
            bind_user=self.config.get('LDAP_BIND_USER_DN'),
            bind_password=self.config.get('LDAP_BIND_USER_PASSWORD'),
        )
        
        try:
            connection.bind()
            log.debug("Successfully bound to LDAP as '{}' for search_bind method".format(
                self.config.get('LDAP_BIND_USER_DN') or 'Anonymous'
            ))
        except Exception as e:
            self.destroy_connection(connection)
            log.error(e)
            raise e

        # Find the user in the search path.
        user_filter = '({search_attr}={username})'.format(
            search_attr=self.config.get('LDAP_USER_LOGIN_ATTR'),
            username=username
        )
        search_filter = '(&{}{})'.format(
            self.config.get('LDAP_USER_OBJECT_FILTER'),
            user_filter,
        )

        connection.search(
            search_base=self.full_user_search_dn,
            search_filter=search_filter,
            search_scope=getattr(ldap3, self.config.get('LDAP_USER_SEARCH_SCOPE')),
            attributes=self.config.get('LDAP_GET_USER_ATTRIBUTES')
        )

        # print(connection.result)
        # print(connection.response)
        response = AuthenticationResponse()

        if len(connection.response) == 0 or \
        (self.config.get('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND')\
        and len(connection.response) > 1):
            # Don't allow them to log in.
            log.debug("Authentication was not successful for user '{}'".format(username))

        else:
            for user in connection.response:
                # Attempt to bind with each user we find until we can find 
                # one that works.
                user_connection = self.make_connection(
                    bind_user=user['dn'],
                    bind_password=password
                )
                log.debug("Directly binding a connection to a server with user:'{}'".format(user['dn']))
                try:
                    user_connection.bind()
                    log.debug("Authentication was successful for user '{}'".format(username))
                    response.status = AuthenticationResponseStatus.success
                    
                    # Populate User Data
                    user['attributes']['dn'] = user['dn']
                    response.user_info = user['attributes']
                    response.user_id = username
                    response.user_dn = user['dn']
                    break


                except ldap3.LDAPInvalidCredentialsResult as e:
                    log.debug("Authentication was not successful for user '{}'".format(username))
                    response.status = AuthenticationResponseStatus.fail
                except Exception as e:
                    self.destroy_connection(user_connection)
                    log.error(e)
                    raise e


        self.destroy_connection(connection)
        return response

    def get_user_groups(self):
        pass

    def get_user_info(self, dn, _connection=None):
        connection = _connection
        if not connection:
            connection = self.make_connection(
                bind_user=app.config.get('LDAP_BIND_USER_DN'),
                bind_password=app.config.get('LDAP_BIND_USER_PASSWORD')
            )
        
        connection.search(
            search_base=dn,
            search_filter=self.config.get('LDAP_USER_OBJECT_FILTER'),
            attributes=self.config.get('LDAP_GET_USER_ATTRIBUTES')
        )

        user_info = None
        if len(connection.response) > 0:
            user_info = connection.response[0]['attributes']
            user_info['dn'] = dn

        if not _connection:
            # We made a connection, so we need to kill it.
            self.destroy_connection(connection)

        return user_info

    def get_group_info(self, dn):
        pass

    def make_connection(self, bind_user=None, bind_password=None):
        authentication = ldap3.AUTH_ANONYMOUS
        if bind_user:
            authentication = getattr(ldap3, self.config.get(
                'LDAP_BIND_AUTHENTICATION_TYPE'))

        connection = ldap3.Connection(
            server=self._server_pool, 
            read_only=True,
            user=bind_user,
            password=bind_password,
            client_strategy=ldap3.STRATEGY_SYNC,
            authentication=authentication,
            check_names=True,
            raise_exceptions=True
        )
        return connection


    def destroy_connection(self, connection):
        connection.unbind()

    @property
    def full_user_search_dn(self):
        return '{user_dn},{base_dn}'.format(
            user_dn=self.config.get('LDAP_USER_DN'),
            base_dn=self.config.get('LDAP_BASE_DN'),
        )

    @property
    def full_group_search_dn(self):
        return '{group_dn},{base_dn}'.format(
            user_dn=self.config.get('LDAP_GROUP_DN'),
            base_dn=self.config.get('LDAP_BASE_DN'),
        )

