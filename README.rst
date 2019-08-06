Flask-LDAP3-Login
============================================

.. image:: https://travis-ci.org/nickw444/flask-ldap3-login.svg?branch=master
    :target: https://travis-ci.org/nickw444/flask-ldap3-login

.. image:: https://coveralls.io/repos/nickw444/flask-ldap3-login/badge.svg
    :target: https://coveralls.io/r/nickw444/flask-ldap3-login

.. image:: https://img.shields.io/pypi/v/flask-ldap3-login.svg
    :target: https://pypi.python.org/pypi/flask-ldap3-login/
    :alt: Latest Version

Maintainer Wanted
-----------------

Back in 2015 I set out to create a new LDAP integration for Flask that was compatible with ``python3-ldap``. At the time, the only LDAP extension for Flask `flask-ldap3-login <https://github.com/ContinuumIO/flask-ldap-login>`_ did not support Python 3.

As time progressed, I moved away from my previous job where LDAP integrations were part of day-to-day client consulting projects, into a software product company working on an entirely different tech stack with no need for anything remotely to do with LDAP. 

Due to this, my focus was taken away from this library. I have too much on my plate to give this library the love it needs and deserves. New features and bug fixes became harder to manually test as I no longer had redily available testing environments, giving me lower confidence in iterating and improving the library.

Due to a high number of open & active issues, I believe there is still some demand for this library, and for this reason alone I do not want to sunset it. I'd rather find a new maintainer who can triage new issues and encourage new contributors to submit patches to fix bugs and add necessary functionality.

**Until a new maintainer is found, issues submitted to this repo will not be actioned.**

If you are interested in becoming a maintainer, please email me at ``flask-ldap3-login [at] nickwhyte [dot] com``, or alternatively raise an issue in this repo.

----

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
