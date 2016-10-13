import mock
from .Directory import get_directory_base
import ldap3
import logging
import re


log = logging.getLogger(__name__)
single_filter = re.compile(r'([A-Za-z0-9_\-]+)=(.+)')


def and_(cmps, data):
    return all([comp(data) for comp in cmps])


def or_(cmps, data):
    return any([comp(data) for comp in cmps])


def build_comparison(cmp_string):
    if cmp_string[0] == '(':
        depth = last_depth = i = 0
        cmps = []

        while i < len(cmp_string):
            if cmp_string[i] == '(':
                depth += 1
                if depth == 1:
                    last_pop = i + 1

            elif cmp_string[i] == ')':
                depth -= 1

            if depth == 0 and last_depth == 1:
                cmps.append(build_comparison(cmp_string[last_pop:i]))

            last_depth = depth
            i += 1
        return cmps

    elif cmp_string[0] == '&':
        cmps = build_comparison(cmp_string[1:])
        return lambda data: and_(cmps, data)

    elif cmp_string[0] == '|':
        cmps = build_comparison(cmp_string[1:])
        return lambda data: or_(cmps, data)

    else:
        match = single_filter.match(cmp_string)
        if match:
            field, value = match.group(1, 2)

            def lamb(data):
                return type(data) == dict and field in data and value in data[field]

            return lamb
        else:
            raise Exception("Malformed Filter '{0}'".format(cmp_string))


class Server(mock.MagicMock):
    pass


class Connection(mock.MagicMock):
    def __init__(self, user=None, password=None, server=None, **kwargs):
        mock.MagicMock.__init__(self)
        self._response = []
        self._result = None
        self.user = user
        self.password = password
        self.server = server
        pass

    def bind(self):
        if not self.server or self.server.servers[0].host != 'ad.mydomain.com':
            raise ldap3.LDAPBindError

        if self.user:
            # Validate the bind user.
            bind_user = get_directory_base(self.user)

            if bind_user and self.password == bind_user['password']:
                return True

            raise ldap3.LDAPInvalidCredentialsResult
        else:
            return True

    def search(self, search_base='', search_filter='(objectClass=*)',
               search_scope=ldap3.SUBTREE, attributes=None):

        log.info("Search began for base '{0}' with filter '{1}' in scope"
                 " '{2}' with attributes '{3}'".format(search_base,
                                                       search_filter,
                                                       search_scope,
                                                       attributes))

        check_user = build_comparison(search_filter)[0]

        scoped_directory = get_directory_base(search_base)

        if search_scope == ldap3.SUBTREE:
            # Perform a recursive search strategy

            def recurse_search(dictionary):

                items = []
                if check_user(dictionary):
                    items.append(dictionary)

                for item in dictionary.values():
                    if check_user(item):
                        items.append(item)

                    if type(item) == dict:
                        items.extend(recurse_search(item))

                return items

            items = recurse_search(scoped_directory)
            items = [dict(attributes=user, dn=user['dn'],
                          type='searchResEntry') for user in items]
            self._result = len(items) > 0
            self._response = items

        elif search_scope == ldap3.LEVEL:

            matching = [dict(attributes=user, dn=user['dn'], type='searchResEntry')
                        for user in scoped_directory.values() if check_user(user)]
            self._result = len(matching) > 0
            self._response = matching

        elif search_scope == ldap3.BASE:
            result = check_user(scoped_directory)
            self._result = result
            if self._result:
                self._response = [scoped_directory]
            else:
                self._response = []

        pass

    @property
    def response(self):
        return self._response

    @property
    def result(self):
        return self._result


class ServerPool(mock.MagicMock):
    pass
