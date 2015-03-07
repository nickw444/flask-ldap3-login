from test_ldap3_login import test_suite


if __name__ == '__main__':
    import logging
    import unittest
    suite = test_suite()
    logging.basicConfig(level=logging.WARNING)
    unittest.main(defaultTest='suite')