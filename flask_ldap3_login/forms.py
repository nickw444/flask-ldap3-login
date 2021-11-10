import logging

import wtforms
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import validators

from flask_ldap3_login import AuthenticationResponseStatus

log = logging.getLogger(__name__)


class LDAPValidationError(validators.ValidationError):
    pass


class LDAPLoginForm(FlaskForm):
    """
    A basic loginform which can be subclassed by your application.
    Upon validation, the form will check against ldap for a valid
    username/password combination.

    Once validiated will have a `form.user` object that contains
    a user object.

    """

    username = wtforms.StringField("Username", validators=[validators.DataRequired()])
    password = wtforms.PasswordField("Password", validators=[validators.DataRequired()])
    submit = wtforms.SubmitField("Submit")
    remember_me = wtforms.BooleanField("Remember Me", default=True)

    def validate_ldap(self):
        logging.debug("Validating LDAPLoginForm against LDAP")
        "Validate the username/password data against ldap directory"
        ldap_mgr = current_app.ldap3_login_manager
        username = self.username.data
        password = self.password.data

        result = ldap_mgr.authenticate(username, password)

        if result.status == AuthenticationResponseStatus.success:
            self.user = ldap_mgr._save_user(
                result.user_dn, result.user_id, result.user_info, result.user_groups
            )
            return True

        else:
            self.user = None
            self.username.errors.append("Invalid Username/Password.")
            self.password.errors.append("Invalid Username/Password.")
            return False

    def validate(self, *args, **kwargs):
        """
        Validates the form by calling `validate` on each field, passing any
        extra `Form.validate_<fieldname>` validators to the field validator.

        also calls `validate_ldap`
        """

        valid = FlaskForm.validate(self, *args, **kwargs)
        if not valid:
            logging.debug(
                "Form validation failed before we had a chance to "
                "check ldap. Reasons: '{}'".format(self.errors)
            )
            return valid

        return self.validate_ldap()
