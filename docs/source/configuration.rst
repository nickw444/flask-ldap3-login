Configuration
=============

The following configuration values are used by Flask-Security:

Core
----

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

======================================== =======================================
``LDAP_PORT``                            Specifies the port to use when 
                                         connecting to LDAP. Defaults to 
                                         ``389``.

``LDAP_HOST``                            Speficies the address of the server to
                                         connect to by default. ``None``.
                                         Additional servers can be added via the
                                         ``add_server`` method.

``LDAP_USE_SSL``                         Specifies whether the default server
                                         connection should use SSL. Defaults to
                                         ``False``.
``LDAP_READONLY``                        Specified if connections made to the 
                                         server are readonly. Defaults to 
                                         ``True``
``LDAP_BIND_DIRECT_CREDENTIALS``         Instead of searching for a DN of a user
                                         you can instead bind directly to the
                                         directory. Setting this ``True`` will 
                                         perform binds without formatting the 
                                         username parameter. This is useful if 
                                         you need to authenticate users with
                                         windows domain notation 
                                         ``myuser@ad.mydomain.com``. Using this
                                         method however limits the info you 
                                         can get from the directory because we 
                                         are unable to get the user's DN to look
                                         up their user info. You will only know
                                         if their credentials are correct or
                                         not. Defaults to ``False``.
``LDAP_ALWAYS_SEARCH_BIND``              Specifies whether or not the library
                                         should perform direct binds. When the 
                                         RDN attribute is the same as the login
                                         attribute, a direct bind will be 
                                         performed automatically. However if 
                                         the user is 
                                         contained within a sub container of the 
                                         ``LDAP_USER_DN``, authentication will
                                         fail. Set this ``True`` to never 
                                         perform a direct bind and instead 
                                         perform a search to look up a user's 
                                         DN. Defaults to ``False``.

``LDAP_BIND_USER_DN``                    Specifies the dn of the user to 
                                         perform search requests with. Defaults 
                                         to ``None``. If None, Anonymous
                                         connections are used.

``LDAP_BIND_USER_PASSWORD``              Specifies the password to bind 
                                         ``LDAP_BIND_USER_DN`` with. Defaults to
                                         ``None``

``LDAP_SEARCH_FOR_GROUPS``               Specifies whether or not groups should
                                         be searched for when getting user details. 
                                         Defaults to ``True``.

``LDAP_FAIL_AUTH_ON_MULTIPLE_FOUND``     Specifies whether or not to fail 
                                         authentication if multiple users 
                                         are found when performing a 
                                         ``bind_search``. Defaults to ``False``

``LDAP_BASE_DN``                         Specifies the base DN for searching.
                                         Defaults to ``''``

``LDAP_USER_DN``                         Specifies the user DN for searching.
                                         Prepended to the base DN to limit the 
                                         scope when searching for users. 
                                         Defaults to ``''``

``LDAP_GROUP_DN``                        Specifies the group DN for searching.
                                         Prepended to the base DN to limit the 
                                         scope when searching for groups. 
                                         Defaults to ``''``

``LDAP_BIND_AUTHENTICATION_TYPE``        Specifies the LDAP bind type to use
                                         when binding to LDAP. Defaults to 
                                         ``'AUTH_SIMPLE'``


======================================== =======================================


Filters/Searching
-----------------

.. tabularcolumns:: |p{6.5cm}|p{8.5cm}|

==================================== ================================================
``LDAP_USER_SEARCH_SCOPE``           Specifies what scope to search in when
                                     searching for a specific user. Defaults to
                                     ``'LEVEL'``.

``LDAP_USER_OBJECT_FILTER``          Specifies what object filter to apply when 
                                     searching for users. Defaults to 
                                     ``'(objectclass=inetorgperson)'``

``LDAP_USER_LOGIN_ATTR``             Declares what ldap attribute corresponds to
                                     the username passed to any login method 
                                     when performing a bind. Defaults to 
                                     ``'uid'``

``LDAP_USER_RDN_ATTR``               Specifies the RDN attribute used in the
                                     directory. Defaults to ``'uid'``


``LDAP_GET_USER_ATTRIBUTES``         Specifies which LDAP attributes to get
                                     when searching LDAP for a user/users.
                                     Defaults to ``ldap3.ALL_ATTRIBUTES``

``LDAP_GROUP_SEARCH_SCOPE``          Specifies what scope to search in when
                                     searching for a specific group. Defaults to
                                     ``'LEVEL'``.

``LDAP_GROUP_OBJECT_FILTER``         Specifies what object filter to apply when 
                                     searching for groups. Defaults to 
                                     ``'(objectclass=group)'``

``LDAP_GROUP_MEMBERS_ATTR``          Specifies the LDAP attribute where group 
                                     members are declared. Defaults to 
                                     ``'uniqueMember'``
                                    
``LDAP_GET_GROUP_ATTRIBUTES``        Specifies which LDAP attributes to get
                                     when searching LDAP for a group/groups.
                                     Defaults to ``ldap3.ALL_ATTRIBUTES``       

==================================== ================================================
