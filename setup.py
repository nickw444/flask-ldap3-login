import os
from setuptools import setup


def get_version():
    version_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'VERSION')
    v = open(version_path).read()
    if type(v) == str:
            return v.strip()
    return v.decode('UTF-8').strip()


readme_path = os.path.join(os.path.dirname(
    os.path.abspath(__file__)),
    'README.rst',
)
long_description = open(readme_path).read()

try:
    version = get_version()
except Exception as e:
    version = '0.0.0-dev'

requires = ['ldap3', 'Flask', 'Flask-wtf']

try:
    import enum  # noqa
except Exception as e:
    requires.append('enum34')


setup(
    name='flask-ldap3-login',
    version=version,
    packages=['flask_ldap3_login'],
    author="Nick Whyte",
    author_email='nick@nickwhyte.com',
    description="LDAP Support for Flask in Python3/2",
    long_description=long_description,
    url='https://github.com/nickw444/flask-ldap3-login',
    zip_safe=False,
    install_requires=requires,
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6',
    ],
    test_suite="flask_ldap3_login_tests",
    tests_require=['mock']
)
