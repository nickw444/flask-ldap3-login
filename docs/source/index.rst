.. flask-ldap-login documentation master file, created by
   sphinx-quickstart on Sat Mar  7 11:57:48 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-LDAP3-Login
============================================

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


.. include:: contents.rst.inc
