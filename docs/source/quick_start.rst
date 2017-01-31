Quick Start
==================================================

Install the Package
~~~~~~~~~~~~~~~~~~~

::

    $ pip install flask-ldap3-login


Basic Application
~~~~~~~~~~~~~~~~~

This is a basic application which uses Flask-Login to handle user sessions. 
The application stores the users in the dictionary ``users``. 

.. literalinclude:: ../../ldap_app.py


Basic Scripting Usage (Without a Flask App)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is an example for if you wish to simply use the module, maybe for testing or for use in some other environment.

.. literalinclude:: ../../ldap_noapp.py


Custom TLS Context
~~~~~~~~~~~~~~~~~~

This is an example that shows how to initialize a custom TLS context for
securing communication between the module and a secure LDAP (LDAPS server.

.. literalinclude:: ../../ldap_noapp.py
