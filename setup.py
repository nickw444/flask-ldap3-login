import os
from setuptools import setup

readme_path = os.path.join(os.path.dirname(
  os.path.abspath(__file__)),
  'README.rst',
)
long_description = open(readme_path).read()
version_path = os.path.join(os.path.dirname(
  os.path.abspath(__file__)),
  'VERSION',
)
version = open(version_path).read()


setup(
  name='flask-boilerplate-utils',
  version=version,
  packages=['flask_ldap3_login'],
  author="Nick Whyte",
  author_email='nick@nickwhyte.com',
  description="Flask-Login support for LDAP3.",
  long_description=long_description,
  url='https://github.com/nickw444/flask-ldap3-login',
  zip_safe=False,
  install_requires=[
        "ldap3",
        "Flask-Login",
        "Flask-Principal",
        "Flask",
        "Flask-wtf"
  ],
)
