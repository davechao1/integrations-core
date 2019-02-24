# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import threading
import warnings
from contextlib import contextmanager

import requests
from six import iteritems, string_types
from urllib3.exceptions import InsecureRequestWarning

from ..config import is_affirmative

STANDARD_FIELDS = {
    'password': None,
    'ssl_ca_cert': None,
    'ssl_cert': None,
    'ssl_ignore_warning': False,
    'ssl_private_key': None,
    'ssl_verify': True,
    'timeout': 10,
    'username': None,
}


class RequestsWrapper(object):
    warning_lock = threading.RLock()

    def __init__(self, instance, remapper=None):
        if remapper is None:
            remapper = {}

        # Populate with the default values
        config = {field: instance.get(field, value) for field, value in iteritems(STANDARD_FIELDS)}

        # Support non-standard (legacy) configurations, for example:
        # {
        #     'disable_ssl_validation': {
        #         'name': 'ssl_verify',
        #         'default': False,
        #         'invert': True,
        #     },
        #     ...
        # }
        for remapped_field, data in iteritems(remapper):
            field = data.get('name')

            # Ignore fields we don't recognize
            if field not in STANDARD_FIELDS:
                continue

            # Get value, with a possible default
            value = instance.get(remapped_field, data.get('default'))

            # Invert booleans if need be
            if isinstance(value, bool) and data.get('invert'):
                value = not value

            config[field] = value

        # http://docs.python-requests.org/en/master/user/advanced/#timeouts
        timeout = int(config['timeout'])

        # http://docs.python-requests.org/en/master/user/authentication/
        auth = None
        if config['username'] and config['password']:
            auth = (config['username'], config['password'])

        # http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        verify = True
        if isinstance(config['ssl_ca_cert'], string_types):
            verify = config['ssl_ca_cert']
        elif not is_affirmative(config['ssl_verify']):
            verify = False

        # http://docs.python-requests.org/en/master/user/advanced/#client-side-certificates
        cert = None
        if isinstance(config['ssl_cert'], string_types):
            if isinstance(config['ssl_private_key'], string_types):
                cert = (config['ssl_cert'], config['ssl_private_key'])
            else:
                cert = config['ssl_cert']

        # Default options
        self.options = {
            'auth': auth,
            'cert': cert,
            'timeout': timeout,
            'verify': verify,
        }

        # Ignore warnings for lack of SSL validation
        self.ignore_ssl_warning = verify is False and config['ssl_ignore_warning']

        # For performance, if desired http://docs.python-requests.org/en/master/user/advanced/#session-objects
        self._session = None

    def get(self, url, persist=False, **options):
        return self._request('get', url, persist, options)

    def post(self, url, persist=False, **options):
        return self._request('post', url, persist, options)

    def head(self, url, persist=False, **options):
        return self._request('head', url, persist, options)

    def put(self, url, persist=False, **options):
        return self._request('put', url, persist, options)

    def patch(self, url, persist=False, **options):
        return self._request('patch', url, persist, options)

    def delete(self, url, persist=False, **options):
        return self._request('delete', url, persist, options)

    def _request(self, method, url, persist, options):
        with self.handle_ssl_warning():
            if persist:
                return getattr(self.session, method)(url, **options)
            else:
                return getattr(requests, method)(url, **self.populate_options(options))

    def populate_options(self, options):
        # Avoid needless dictionary update if there are no options
        if not options:
            return self.options

        for option, value in iteritems(self.options):
            # Make explicitly set options take precedence
            options.setdefault(option, value)

        return options

    @contextmanager
    def handle_ssl_warning(self):
        # Currently this doesn't actually do anything because a re-entrant
        # lock doesn't protect resources in the same thread, which is very
        # important as the Agent only uses one thread and disregards the GIL.
        with self.warning_lock:

            with warnings.catch_warnings():
                if self.ignore_ssl_warning:
                    warnings.simplefilter('ignore', InsecureRequestWarning)
                # Explicitly reset filter in case we're already ignoring in another
                # instance's lock. Remove this when we start using a real lock.
                else:
                    warnings.simplefilter('always', InsecureRequestWarning)

                yield

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()

            # Attributes can't be passed in the constructor
            for option, value in iteritems(self.options):
                setattr(self._session, option, value)

        return self._session

    def __del__(self):
        if self._session is not None:
            self._session.close()
