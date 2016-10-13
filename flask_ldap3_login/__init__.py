import logging
import ldap3

try:
    from flask import _app_ctx_stack as stack
except ImportError:  # pragma: no cover
    from flask import _request_ctx_stack as stack

from enum import Enum

log = logging.getLogger(__name__)

AuthenticationResponseStatus = Enum(
    'AuthenticationResponseStatus', 'fail success')


class AuthenticationResponse(object):
    """
    A response object when authenticating. Lets us pass status codes around
    and also user data.

    Args:
        status (AuthenticationResponseStatus):  The status of the result.
        user_info (dict): User info dictionary obtained from LDAP.
        user_id (str): User id used to authenticate to LDAP with.
        user_dn (str): User DN found from LDAP.
        user_groups (list): A list containing a dicts of group info.
    """

    def __init__(self, status=AuthenticationResponseStatus.fail,
                 user_info=None, user_id=None, user_dn=None, user_groups=[]):

        self.user_info = user_info,
        self.user_id = user_id,
        self.user_dn = user_dn,
        self.user_groups = user_groups
        self.status = status


class LDAP3LoginManager(object):
    """
    Initialise a LDAP3LoginManager. If app is passed, init_app is called
    within this call.

    Args:
        app (flask.Flask): The flask app to initialise with
    """

    def __init__(self, app=None):

        self._save_user = None
        self.config = {}
        self._server_pool = ldap3.ServerPool(
            [],
            ldap3.POOLING_STRATEGY_FIRST,
            active=1,   # Loop through all servers once.
            exhaust=10,  # Remove unreachable servers for 10 seconds.
        )

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        '''
        Configures this extension with the given app. This registers an
        ``teardown_appcontext`` call, and attaches this ``LDAP3LoginManager``
        to it as ``app.ldap3_login_manager``.

        Args:
            app (flask.Flask): The flask app to initialise with
        '''

        app.ldap3_login_manager = self

        servers = list(self._server_pool)
        for s in servers:
            self._server_pool.remove(s)

        self.init_config(app.config)

        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown)
        else:  # pragma: no cover
            app.teardown_request(self.teardown)

        self.app = app

    def init_config(self, config):
        '''
        Configures this extension with a given configuration dictionary.
        This allows use of this extension without a flask app.

        Args:
            config (dict): A dictionary with configuration keys
        '''

        self.config.update(config)

        self.config.setdefault('LDAP_PORT', 389)
        self.config.setdefault('LDAP_HOST', None)
        self.config.setdefault('LDAP_USE_SSL', False)
        self.config.setdefault('LDAP_READONLY', True)
        self.config.setdefault('LDAP_BIND_DIRECT_CREDENTIALS', False)
        self.config.setdefault('LDAP_BIND_DIRECT_SUFFIX', '')
        self.config.setdefault('LDAP_BIND_DIRECT_GET_USER_INFO', True)
        self.config.setdefault('LDAP_ALWAYS_SEARCH_BIND', False)
        self.config.setdefault('LDAP_BASE_DN', '')
        self.config.setdefault('LDAP_BIND_USER_DN', None)
        self.config.setdefault('LDAP_BIND_USER_PASSWORD', None)
        self.config.setdefault('LDAP_SEARCH_FOR_GROUPS', True)
        self.config.setdefault('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND', False)

        # Prepended to the Base DN to limit scope when searching for
        # Users/Groups.
        self.config.setdefault('LDAP_USER_DN', '')
        self.config.setdefault('LDAP_GROUP_DN', '')

        self.config.setdefault('LDAP_BIND_AUTHENTICATION_TYPE', 'AUTH_SIMPLE')

        # Ldap Filters
        self.config.setdefault('LDAP_USER_SEARCH_SCOPE',
                               'SEARCH_SCOPE_SINGLE_LEVEL')
        self.config.setdefault('LDAP_USER_OBJECT_FILTER',
                               '(objectclass=person)')
        self.config.setdefault('LDAP_USER_LOGIN_ATTR', 'uid')
        self.config.setdefault('LDAP_USER_RDN_ATTR', 'uid')
        self.config.setdefault(
            'LDAP_GET_USER_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)

        self.config.setdefault('LDAP_GROUP_SEARCH_SCOPE',
                               'SEARCH_SCOPE_SINGLE_LEVEL')
        self.config.setdefault(
            'LDAP_GROUP_OBJECT_FILTER', '(objectclass=group)')
        self.config.setdefault('LDAP_GROUP_MEMBERS_ATTR', 'uniqueMember')
        self.config.setdefault(
            'LDAP_GET_GROUP_ATTRIBUTES', ldap3.ALL_ATTRIBUTES)

        self.add_server(
            hostname=self.config.get('LDAP_HOST'),
            port=self.config.get('LDAP_PORT'),
            use_ssl=self.config.get('LDAP_USE_SSL')
        )

    def add_server(self, hostname, port, use_ssl):
        """
        Add an additional server to the server pool and return the
        freshly created server.

        Args:
            hostname (str): Hostname of the server
            port (int): Port of the server
            use_ssl (bool): True if SSL is to be used when connecting.

        Returns:
            ldap3.Server: The freshly created server object.
        """
        server = ldap3.Server(hostname, port=port, use_ssl=use_ssl)
        self._server_pool.add(server)
        return server

    def _contextualise_connection(self, connection):
        """
        Add a connection to the appcontext so it can be freed/unbound at
        a later time if an exception occured and it was not freed.

        Args:
            connection (ldap3.Connection): Connection to add to the appcontext

        """

        ctx = stack.top
        if ctx is not None:
            if not hasattr(ctx, 'ldap3_manager_connections'):
                ctx.ldap3_manager_connections = [connection]
            else:
                ctx.ldap3_manager_connections.append(connection)

    def _decontextualise_connection(self, connection):
        """
        Remove a connection from the appcontext.

        Args:
            connection (ldap3.Connection): connection to remove from the
                appcontext

        """

        ctx = stack.top
        if ctx is not None and connection in ctx.ldap3_manager_connections:
            ctx.ldap3_manager_connections.remove(connection)

    def teardown(self, exception):
        """
        Cleanup after a request. Close any open connections.
        """

        ctx = stack.top
        if ctx is not None:
            if hasattr(ctx, 'ldap3_manager_connections'):
                for connection in ctx.ldap3_manager_connections:
                    self.destroy_connection(connection)
            if hasattr(ctx, 'ldap3_manager_main_connection'):
                log.debug(
                    "Unbinding a connection used within the request context.")
                ctx.ldap3_manager_main_connection.unbind()
                ctx.ldap3_manager_main_connection = None

    def save_user(self, callback):
        '''
        This sets the callback for saving a user that has been looked up from
        from ldap.

        The function you set should take a user dn (unicode), username
        (unicode) and userdata (dict), and memberships (list).

        ::

            @ldap3_manager.save_user
            def save_user(dn, username, userdata, memberships):
                return User(username=username, data=userdata)

        Your callback function MUST return the user object in your ORM
        (or similar). as this is used within the LoginForm and placed
        at ``form.user``

        Args:
            callback (function): The function to be used as the save user
                                 callback.
        '''

        self._save_user = callback
        return callback

    def authenticate(self, username, password):
        """
        An abstracted authentication method. Decides whether to perform a
        direct bind or a search bind based upon the login attribute configured
        in the config.

        Args:
            username (str): Username of the user to bind
            password (str): User's password to bind with.

        Returns:
            AuthenticationResponse

        """
        if self.config.get('LDAP_BIND_DIRECT_CREDENTIALS'):
            result = self.authenticate_direct_credentials(username, password)

        elif not self.config.get('LDAP_ALWAYS_SEARCH_BIND') and \
                self.config.get('LDAP_USER_RDN_ATTR') == \
                self.config.get('LDAP_USER_LOGIN_ATTR'):
            # Since the user's RDN is the same as the login field,
            # we can do a direct bind.
            result = self.authenticate_direct_bind(username, password)
        else:
            # We need to search the User's DN to find who the user is (and
            # their DN) so we can try bind with their password.
            result = self.authenticate_search_bind(username, password)

        return result

    def authenticate_direct_credentials(self, username, password):
        """
        Performs a direct bind, however using direct credentials. Can be used
        if interfacing with an Active Directory domain controller which
        authenticates using username@domain.com directly.

        Performing this kind of lookup limits the information we can get from
        ldap. Instead we can only deduce whether or not their bind was
        successful. Do not use this method if you require more user info.

        Args:
            username (str): username for the user to bind with. LOGIN_SUFFIX
                            will be appended.
            password (str): User's password to bind with.

        Returns:
            AuthenticationResponse
        """

        connection = self._make_connection(
            bind_user=username + self.config.get('LDAP_BIND_DIRECT_SUFFIX'),
            bind_password=password,
        )

        response = AuthenticationResponse()
        try:
            connection.bind()
            response.status = AuthenticationResponseStatus.success
            response.user_id = username
            log.debug(
                "Authentication was successful for user '{0}'".format(username))

            if self.config.get('LDAP_BIND_DIRECT_GET_USER_INFO'):
                # User wants extra info about the bind
                user_filter = '({search_attr}={username})'.format(
                    search_attr=self.config.get('LDAP_USER_LOGIN_ATTR'),
                    username=username
                )
                search_filter = '(&{0}{1})'.format(
                    self.config.get('LDAP_USER_OBJECT_FILTER'),
                    user_filter,
                )

                connection.search(
                    search_base=self.full_user_search_dn,
                    search_filter=search_filter,
                    search_scope=getattr(
                        ldap3, self.config.get('LDAP_USER_SEARCH_SCOPE')),
                    attributes=self.config.get('LDAP_GET_USER_ATTRIBUTES'),
                )

                if len(connection.response) == 0 or \
                    (self.config.get('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND') and
                        len(connection.response) > 1):
                    # Don't allow them to log in.
                    log.error(
                        "Could not gather extra info for user '{0}'".format(username))
                else:

                    user = connection.response[0]
                    user['attributes']['dn'] = user['dn']
                    response.user_info = user['attributes']
                    response.user_dn = user['dn']

        except ldap3.LDAPInvalidCredentialsResult as e:
            log.debug(
                "Authentication was not successful for user '{0}'".format(username))
            response.status = AuthenticationResponseStatus.fail
        except Exception as e:
            log.error(e)
            response.status = AuthenticationResponseStatus.fail

        self.destroy_connection(connection)
        return response

    def authenticate_direct_bind(self, username, password):
        """
        Performs a direct bind. We can do this since the RDN is the same
        as the login attribute. Hence we just string together a dn to find
        this user with.

        Args:
            username (str): Username of the user to bind (the field specified
                as LDAP_BIND_RDN_ATTR)
            password (str): User's password to bind with.

        Returns:
            AuthenticationResponse
        """

        bind_user = '{rdn}={username},{user_search_dn}'.format(
            rdn=self.config.get('LDAP_USER_RDN_ATTR'),
            username=username,
            user_search_dn=self.full_user_search_dn,
        )

        connection = self._make_connection(
            bind_user=bind_user,
            bind_password=password,
        )

        response = AuthenticationResponse()

        try:
            connection.bind()
            log.debug(
                "Authentication was successful for user '{0}'".format(username))
            response.status = AuthenticationResponseStatus.success
            # Get user info here.

            user_info = self.get_user_info(
                dn=bind_user, _connection=connection)
            response.user_dn = bind_user
            response.user_id = username
            response.user_info = user_info
            if self.config.get('LDAP_SEARCH_FOR_GROUPS'):
                response.user_groups = self.get_user_groups(
                    dn=bind_user, _connection=connection)

        except ldap3.LDAPInvalidCredentialsResult as e:
            log.debug(
                "Authentication was not successful for user '{0}'".format(username))
            response.status = AuthenticationResponseStatus.fail
        except Exception as e:
            log.error(e)
            response.status = AuthenticationResponseStatus.fail

        self.destroy_connection(connection)
        return response

    def authenticate_search_bind(self, username, password):
        """
        Performs a search bind to authenticate a user. This is
        required when a the login attribute is not the same
        as the RDN, since we cannot string together their DN on
        the fly, instead we have to find it in the LDAP, then attempt
        to bind with their credentials.

        Args:
            username (str): Username of the user to bind (the field specified
                            as LDAP_BIND_LOGIN_ATTR)
            password (str): User's password to bind with when we find their dn.

        Returns:
            AuthenticationResponse

        """
        connection = self._make_connection(
            bind_user=self.config.get('LDAP_BIND_USER_DN'),
            bind_password=self.config.get('LDAP_BIND_USER_PASSWORD'),
        )

        try:
            connection.bind()
            log.debug("Successfully bound to LDAP as '{0}' for search_bind method".format(
                self.config.get('LDAP_BIND_USER_DN') or 'Anonymous'
            ))
        except Exception as e:
            self.destroy_connection(connection)
            log.error(e)
            return AuthenticationResponse()

        # Find the user in the search path.
        user_filter = '({search_attr}={username})'.format(
            search_attr=self.config.get('LDAP_USER_LOGIN_ATTR'),
            username=username
        )
        search_filter = '(&{0}{1})'.format(
            self.config.get('LDAP_USER_OBJECT_FILTER'),
            user_filter,
        )

        log.debug("Performing an LDAP Search using filter '{0}', base '{1}', "
                  "and scope '{2}'".format(
                      search_filter,
                      self.full_user_search_dn,
                      self.config.get('LDAP_USER_SEARCH_SCOPE')
                  ))

        connection.search(
            search_base=self.full_user_search_dn,
            search_filter=search_filter,
            search_scope=getattr(
                ldap3, self.config.get('LDAP_USER_SEARCH_SCOPE')),
            attributes=self.config.get('LDAP_GET_USER_ATTRIBUTES')
        )

        response = AuthenticationResponse()

        if len(connection.response) == 0 or \
            (self.config.get('LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND') and
                len(connection.response) > 1):
            # Don't allow them to log in.
            log.debug(
                "Authentication was not successful for user '{0}'".format(username))

        else:
            for user in connection.response:
                # Attempt to bind with each user we find until we can find
                # one that works.

                if 'type' not in user or user.get('type') != 'searchResEntry':
                    # Issue #13 - Don't return non-entry results.
                    continue

                user_connection = self._make_connection(
                    bind_user=user['dn'],
                    bind_password=password
                )

                log.debug(
                    "Directly binding a connection to a server with "
                    "user:'{0}'".format(user['dn']))
                try:
                    user_connection.bind()
                    log.debug(
                        "Authentication was successful for user '{0}'".format(username))
                    response.status = AuthenticationResponseStatus.success

                    # Populate User Data
                    user['attributes']['dn'] = user['dn']
                    response.user_info = user['attributes']
                    response.user_id = username
                    response.user_dn = user['dn']
                    if self.config.get('LDAP_SEARCH_FOR_GROUPS'):
                        response.user_groups = self.get_user_groups(
                            dn=user['dn'], _connection=connection)
                    self.destroy_connection(user_connection)
                    break

                except ldap3.LDAPInvalidCredentialsResult as e:
                    log.debug(
                        "Authentication was not successful for "
                        "user '{0}'".format(username))
                    response.status = AuthenticationResponseStatus.fail
                except Exception as e:  # pragma: no cover
                    # This should never happen, however in case ldap3 does ever
                    # throw an error here, we catch it and log it
                    log.error(e)
                    response.status = AuthenticationResponseStatus.fail

                self.destroy_connection(user_connection)

        self.destroy_connection(connection)
        return response

    def get_user_groups(self, dn, group_search_dn=None, _connection=None):
        """
        Gets a list of groups a user at dn is a member of

        Args:
            dn (str): The dn of the user to find memberships for.
            _connection (ldap3.Connection): A connection object to use when
                searching. If not given, a temporary connection will be
                created, and destroyed after use.
            group_search_dn (str): The search dn for groups. Defaults to
                ``'{LDAP_GROUP_DN},{LDAP_BASE_DN}'``.

        Returns:
            list: A list of LDAP groups the user is a member of.
        """

        connection = _connection
        if not connection:
            connection = self._make_connection(
                bind_user=self.config.get('LDAP_BIND_USER_DN'),
                bind_password=self.config.get('LDAP_BIND_USER_PASSWORD')
            )
            connection.bind()

        search_filter = '(&{group_filter}({members_attr}={user_dn}))'.format(
            group_filter=self.config.get('LDAP_GROUP_OBJECT_FILTER'),
            members_attr=self.config.get('LDAP_GROUP_MEMBERS_ATTR'),
            user_dn=dn
        )

        log.debug("Searching for groups for specific user with filter '{0}' "
                  ", base '{1}' and scope '{2}'".format(
                      search_filter,
                      group_search_dn or self.full_group_search_dn,
                      self.config.get('LDAP_GROUP_SEARCH_SCOPE')
                  ))

        connection.search(
            search_base=group_search_dn or self.full_group_search_dn,
            search_filter=search_filter,
            attributes=self.config.get('LDAP_GET_GROUP_ATTRIBUTES'),
            search_scope=getattr(
                ldap3, self.config.get('LDAP_GROUP_SEARCH_SCOPE'))
        )

        results = []
        for item in connection.response:
            if 'type' not in item or item.get('type') != 'searchResEntry':
                # Issue #13 - Don't return non-entry results.
                continue

            group_data = item['attributes']
            group_data['dn'] = item['dn']
            results.append(group_data)

        if not _connection:
            # We made a connection, so we need to kill it.
            self.destroy_connection(connection)

        return results

    def get_user_info(self, dn, _connection=None):
        """
        Gets info about a user specified at dn.

        Args:
            dn (str): The dn of the user to find
            _connection (ldap3.Connection): A connection object to use when
                searching. If not given, a temporary connection will be
                created, and destroyed after use.

        Returns:
            dict: A dictionary of the user info from LDAP

        """
        return self.get_object(
            dn=dn,
            filter=self.config.get('LDAP_USER_OBJECT_FILTER'),
            attributes=self.config.get("LDAP_GET_USER_ATTRIBUTES"),
            _connection=_connection,
        )

    def get_user_info_for_username(self, username, _connection=None):
        """
        Gets info about a user at a specified username by searching the
        Users DN. Username attribute is the same as specified as
        LDAP_USER_LOGIN_ATTR.


        Args:
            username (str): Username of the user to search for.
            _connection (ldap3.Connection): A connection object to use when
                searching. If not given, a temporary connection will be
                created, and destroyed after use.
        Returns:
            dict: A dictionary of the user info from LDAP
        """
        ldap_filter = '(&({0}={1}){2})'.format(
            self.config.get('LDAP_USER_LOGIN_ATTR'),
            username,
            self.config.get('LDAP_USER_OBJECT_FILTER')
        )

        return self.get_object(
            dn=self.full_user_search_dn,
            filter=ldap_filter,
            attributes=self.config.get("LDAP_GET_USER_ATTRIBUTES"),
            _connection=_connection,
        )

    def get_group_info(self, dn, _connection=None):
        """
        Gets info about a group specified at dn.

        Args:
            dn (str): The dn of the group to find
            _connection (ldap3.Connection): A connection object to use when
                searching. If not given, a temporary connection will be
                created, and destroyed after use.

        Returns:
            dict: A dictionary of the group info from LDAP
        """

        return self.get_object(
            dn=dn,
            filter=self.config.get('LDAP_GROUP_OBJECT_FILTER'),
            attributes=self.config.get("LDAP_GET_GROUP_ATTRIBUTES"),
            _connection=_connection,
        )

    def get_object(self, dn, filter, attributes, _connection=None):
        """
        Gets an object at the specified dn and returns it.

        Args:
            dn (str): The dn of the object to find.
            filter (str): The LDAP syntax search filter.
            attributes (list): A list of LDAP attributes to get when searching.
            _connection (ldap3.Connection): A connection object to use when
                searching. If not given, a temporary connection will be created,
                and destroyed after use.

        Returns:
            dict: A dictionary of the object info from LDAP
        """

        connection = _connection
        if not connection:
            connection = self._make_connection(
                bind_user=self.config.get('LDAP_BIND_USER_DN'),
                bind_password=self.config.get('LDAP_BIND_USER_PASSWORD')
            )
            connection.bind()

        connection.search(
            search_base=dn,
            search_filter=filter,
            attributes=attributes,
        )

        data = None
        if len(connection.response) > 0:
            data = connection.response[0]['attributes']
            data['dn'] = connection.response[0]['dn']

        if not _connection:
            # We made a connection, so we need to kill it.
            self.destroy_connection(connection)

        return data

    @property
    def connection(self):
        """
        Convenience property for externally accessing an authenticated
        connection to the server. This connection is automatically
        handled by the appcontext, so you do not have to perform an unbind.

        Returns:
            ldap3.Connection: A bound ldap3.Connection
        Raises:
            ldap3.core.exceptions.LDAPException: Since this method is performing
                a bind on behalf of the caller. You should handle this case
                occuring, such as invalid service credentials.
        """
        ctx = stack.top
        if ctx is None:
            raise Exception("Working outside of the Flask application "
                            "context. If you wish to make a connection outside of a flask"
                            " application context, please handle your connections "
                            "and use manager.make_connection()")

        if hasattr(ctx, 'ldap3_manager_main_connection'):
            return ctx.ldap3_manager_main_connection
        else:
            connection = self._make_connection(
                bind_user=self.config.get('LDAP_BIND_USER_DN'),
                bind_password=self.config.get('LDAP_BIND_USER_PASSWORD'),
                contextualise=False
            )
            connection.bind()
            if ctx is not None:
                ctx.ldap3_manager_main_connection = connection
            return connection

    def make_connection(self, bind_user=None, bind_password=None, **kwargs):
        """
        Make a connection to the LDAP Directory.

        Args:
            bind_user (str): User to bind with. If `None`, AUTH_ANONYMOUS is
                used, otherwise authentication specified with
                config['LDAP_BIND_AUTHENTICATION_TYPE'] is used.
            bind_password (str): Password to bind to the directory with
            **kwargs (dict): Additional arguments to pass to the
                ``ldap3.Connection``

        Returns:
            ldap3.Connection: An unbound ldap3.Connection. You should handle exceptions
                upon bind if you use this internal method.
        """

        return self._make_connection(bind_user, bind_password,
                                     contextualise=False, **kwargs)

    def _make_connection(self, bind_user=None, bind_password=None,
                         contextualise=True, **kwargs):
        """
        Make a connection.

        Args:
            bind_user (str): User to bind with. If `None`, AUTH_ANONYMOUS is
                used, otherwise authentication specified with
                config['LDAP_BIND_AUTHENTICATION_TYPE'] is used.
            bind_password (str): Password to bind to the directory with
            contextualise (bool): If true (default), will add this connection to the
                appcontext so it can be unbound upon app_teardown.

        Returns:
            ldap3.Connection: An unbound ldap3.Connection. You should handle exceptions
                upon bind if you use this internal method.
        """

        authentication = ldap3.AUTH_ANONYMOUS
        if bind_user:
            authentication = getattr(ldap3, self.config.get(
                'LDAP_BIND_AUTHENTICATION_TYPE'))

        log.debug("Opening connection with bind user '{0}'".format(
            bind_user or 'Anonymous'))
        connection = ldap3.Connection(
            server=self._server_pool,
            read_only=self.config.get('LDAP_READONLY'),
            user=bind_user,
            password=bind_password,
            client_strategy=ldap3.STRATEGY_SYNC,
            authentication=authentication,
            check_names=True,
            raise_exceptions=True,
            **kwargs
        )

        if contextualise:
            self._contextualise_connection(connection)
        return connection

    def destroy_connection(self, connection):
        """
        Destroys a connection. Removes the connection from the appcontext, and
        unbinds it.

        Args:
            connection (ldap3.Connection):  The connnection to destroy
        """

        log.debug("Destroying connection at <{0}>".format(hex(id(connection))))
        self._decontextualise_connection(connection)
        connection.unbind()

    @property
    def full_user_search_dn(self):
        """
        Returns a the base search DN with the user search DN prepended.

        Returns:
            str: Full user search dn
        """
        return self.compiled_sub_dn(self.config.get('LDAP_USER_DN'))

    @property
    def full_group_search_dn(self):
        """
        Returns a the base search DN with the group search DN prepended.

        Returns:
            str: Full group search dn
        """
        return self.compiled_sub_dn(self.config.get('LDAP_GROUP_DN'))

    def compiled_sub_dn(self, prepend):
        """
        Returns:
            str: A DN with the DN Base appended to the end.

        Args:
            prepend (str): The dn to prepend to the base.
        """
        prepend = prepend.strip()
        if prepend == '':
            return self.config.get('LDAP_BASE_DN')
        return '{prepend},{base}'.format(
            prepend=prepend,
            base=self.config.get('LDAP_BASE_DN')
        )
