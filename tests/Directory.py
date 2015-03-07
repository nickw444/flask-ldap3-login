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
