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


Basic Scripting Usage
~~~~~~~~~~~~~~~~~~~~~

Using this module without a Flask application is no longer supported.
(It is a Flask plugin, after all.)
However, it can be useful to have scripts along with a Flask application.
Flask supports this through the ``flask`` command-line tool,
see `Flask's documentation <https://flask.palletsprojects.com/en/1.1.x/>`_ for details.
Here's a quick example of a command you could add to the above app::

    @app.cli.command('check-credentials')
    @click.password_option(confirm=False)
    @click.argument('username')
    def check_credentials(username, password):
        click.echo(ldap_manager.authenticate(username, password))

Custom TLS Context
~~~~~~~~~~~~~~~~~~

This example is the app from before modified to use a custom TLS context
for securing communication to a secure LDAP (LDAPS) server.

.. literalinclude:: ../../ldap_app_tls.py
