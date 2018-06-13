DIRECTORY = {
    'dc=com': {
        'dc=mydomain': {
            'cn=Bind': {
                'cn': ['BIND'],
                'mail': ['bind@localhost.com'],
                'objectclass': ['person'],
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
                    'objectclass': ['person'],
                    'dn': 'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                    'password': 'fake123'
                },
                'cn=Fake User': {
                    'cn': ['Fake User'],
                    'mail': ['fake@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['User'],
                    'givenname': ['Fake'],
                    'objectclass': ['person'],
                    'dn': 'cn=Fake User,ou=users,dc=mydomain,dc=com',
                    'password': 'fake321',
                },
                'cn=Prefix Fake User': {
                    'cn': ['Prefix Fake User'],
                    'mail': ['fake@nickwhyte.com'],
                    'website': ['http://www.nickwhyte.com'],
                    'sn': ['User'],
                    'givenname': ['Fake'],
                    'objectclass': ['person'],
                    'dn': 'cn=Fake User,ou=users,dc=mydomain,dc=com',
                    'password': 'fake321',
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
                    'objectclass': ['group'],
                    'dn': 'cn=Staff,ou=groups,dc=mydomain,dc=com',
                },
                'cn=Admins': {
                    'cn': ['Admins'],
                    'description': ['A Group for Admins'],
                    'uniqueMember': [
                        'cn=Nick Whyte,ou=users,dc=mydomain,dc=com',
                    ],
                    'objectclass': ['group'],
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
