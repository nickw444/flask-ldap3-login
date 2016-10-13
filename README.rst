Flask-LDAP3-Login
============================================
.. image:: https://travis-ci.org/nickw444/flask-ldap3-login.svg?branch=master
    :target: https://travis-ci.org/nickw444/flask-ldap3-login

.. image:: https://coveralls.io/repos/nickw444/flask-ldap3-login/badge.svg
    :target: https://coveralls.io/r/nickw444/flask-ldap3-login

.. image:: https://img.shields.io/pypi/v/flask-ldap3-login.svg
    :target: https://pypi.python.org/pypi/flask-ldap3-login/
    :alt: Latest Version


Flask LDAP3 Login allows you to easily integrate your flask app with an LDAP
directory. It can be used as an extension to Flask-Login and can even be used
with Flask-Principal for permission and privilege management.

Flask LDAP3 Login  uses the `ldap3 <http://ldap3.readthedocs.org/en/latest/>`_ library, maintaining compatability with 
python 3.4 and backwards. 

Flask LDAP3 Login **Will**:
    * Allow you to query whether or not a user's credentials are correct
    * Query the directory for users details
    * Query the directory for group details
    * Query the directory for users group memberships
    * Provide a contextual ``ldap_manager.connection`` object (``ldap3.Connection``)
      which can be used in any flask request context. Useful for writing
      your own more advanced queries.
    
Flask LDAP3 Login **Wont**:
    * Provide a login/logout mechanism. You need to provide this with something
      like `flask-login <https://flask-login.readthedocs.org/en/latest/>`_
    * Provide any extension to the application's session. User tracking  and 
      group tracking should be done via `flask-login <https://flask-login.readthedocs.org/en/latest/>`_ and `flask-principal <https://pythonhosted.org/Flask-Principal/>`_  


`View the Full Documentation at ReadTheDocs <http://flask-ldap3-login.readthedocs.org/en/latest/>`_