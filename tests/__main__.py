from test_ldap3_login import BasicTestCase


if __name__ == '__main__':
    import logging
    import unittest
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(BasicTestCase))
    logging.basicConfig(level=logging.DEBUG)
    unittest.main(defaultTest='suite')