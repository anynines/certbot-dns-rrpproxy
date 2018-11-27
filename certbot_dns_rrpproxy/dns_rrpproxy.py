"""DNS Authenticator using RRPProxy API."""
import httplib
import logging
import urllib
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

# from xmlrpc.client import ServerProxy, Error

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using RRPProxy API

    This Authenticator uses RRPProxy API to fulfull a dns-01 challenge.
    """

    description = ('Create or update a DNS TXT record for a given domain zone at RRPproxy.')
    long_description = 'Create or update a DNS TXT record for a given domain zone at RRPproxy.'

    RRP_SERVER = 'api.rrpproxy.net'
    RRP_SERVER_STAGING = 'api-ote.rrpproxy.net'
    RRP_REQUEST_URI = '/api/call'
    RRP_PROPAGATION_SECONDS = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.server = self.RRP_SERVER
        self.request_uri = self.RRP_REQUEST_URI
        self.credentials = None
        self.propagation_seconds = self.RRP_PROPAGATION_SECONDS

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='RRPproxy credentials INI file.')
        add('propagation_seconds', type=int, default=60, help='Number of secs. to wait for DNS propagation.')
        add('staging', action='store_true', help='Whether this is a test run (OTE).')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RRPProxy API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'RRPproxy credentials INI file',
            {
                's_login': 'login name',
                's_pw': 'password'
            }
        )

    def _perform(self, _domain, validation_name, validation):
        self._get_rrpproxy_client().add_txt_record(_domain, validation_name, validation, self.conf('propagation_seconds'))

    def _cleanup(self, _domain, validation_name, validation):
        self._get_rrpproxy_client().del_txt_record(_domain, validation_name, validation)

    def _get_rrpproxy_client(self):
        if self.conf('staging'):
            self.server = self.RRP_SERVER_STAGING

        return _RRPProxyClient(self.server,
                               self.request_uri,
                               self.credentials.conf('s_login'),
                               self.credentials.conf('s_pw'),
                               self.conf('staging'))

class _RRPProxyClient(object):
    """
    Encapsulates all communication with the target DNS server.
    """
    def __init__(self, server, uri, login, password, staging):
        self.server = server
        self.uri = uri
        self.login = login
        self.password = password
        self.staging = staging

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        conn = httplib.HTTPSConnection(self.server)
        conn.set_debuglevel(1)
        try:
            logger.info('authenticating domain: %s' % domain)
            logger.info('authenticating record_name: %s' % record_name)
            logger.info('authenticating record_content: %s' % record_content)
            logger.info('authenticating record_ttl: %s' % record_ttl)
            params_hash = {
                's_login': self.login,
                's_pw': self.password,
                'command': 'QueryDnsZoneRRList',
                'dnszone': domain
            }

            if self.staging:
                params_hash['s_opmode'] = 'OTE'

            params = urllib.urlencode(params_hash)

            conn.request('GET', self.uri + '?' + params)
            response = conn.getresponse()
            logger.info('response.status: %s' % response.status)
            logger.info('response.reason: %s' % response.reason)
            data = response.read()
            logger.info('response.data: %s' % data)
        except httplib.HTTPException as v:
            logger.error(v)

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """
