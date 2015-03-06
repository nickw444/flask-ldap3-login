import unittest
import flask.ext.ldap3_login as ldap3_login
import flask 


class BasicTestCase(unittest.TestCase):

    def setUp(self):
        app = flask.Flask(__name__)
        app.config['LDAP_HOST'] = ''
        app.config['LDAP_USER_DN'] = ''
        app.config['LDAP_GROUP_DN'] = ''
        app.config['LDAP_BASE_DN'] = ''
        app.config['LDAP_USER_RDN_ATTR'] = 'cn'
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
        r = self.manager.authenticate('', '')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(BasicTestCase))
    return suite

if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)
    unittest.main(defaultTest='suite')