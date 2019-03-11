from flask_ldap3_login import LDAP3LoginManager
from ldap3 import Tls
import ssl

config = dict()

# Setup LDAP Configuration Variables. Change these to your own settings.
# All configuration directives can be found in the documentation.

# Hostname of your LDAP Server
config['LDAP_HOST'] = 'ad.mydomain.com'

# Port number of your LDAP server
config['LDAP_PORT'] = 636

# Base DN of your directory
config['LDAP_BASE_DN'] = 'dc=mydomain,dc=com'

# Users DN to be prepended to the Base DN
config['LDAP_USER_DN'] = 'ou=users'

# Groups DN to be prepended to the Base DN
config['LDAP_GROUP_DN'] = 'ou=groups'


# The RDN attribute for your user schema on LDAP
config['LDAP_USER_RDN_ATTR'] = 'cn'

# The Attribute you want users to authenticate to LDAP with.
config['LDAP_USER_LOGIN_ATTR'] = 'mail'

# The Username to bind to LDAP with
config['LDAP_BIND_USER_DN'] = None

# The Password to bind to LDAP with
config['LDAP_BIND_USER_PASSWORD'] = None

# Specify the server connection should use SSL
config['LDAP_USE_SSL'] = True

# Instruct Flask-LDAP3-Login to not automatically add the server
config['LDAP_ADD_SERVER'] = False

# Setup a LDAP3 Login Manager.
ldap_manager = LDAP3LoginManager()

# Init the mamager with the config since we aren't using an app
ldap_manager.init_config(config)


# Initialize a `Tls` context, and add the server manually. See
# http://ldap3.readthedocs.io/ssltls.html for more information.
tls_ctx = Tls(
    validate=ssl.CERT_REQUIRED,
    version=ssl.PROTOCOL_TLSv1,
    ca_certs_file='/path/to/cacerts'
)

ldap_manager.add_server(
    config.get('LDAP_HOST'),
    config.get('LDAP_PORT'),
    config.get('LDAP_USE_SSL'),
    tls_ctx=tls_ctx
)

# Check if the credentials are correct
response = ldap_manager.authenticate('username', 'password')
print(response.status)
