"""DNS Authenticator using RRPProxy API."""
import httplib
import logging
import urllib
import re
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

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
    RRP_PROPAGATION_SECONDS = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.server = self.RRP_SERVER
        self.request_uri = self.RRP_REQUEST_URI
        self.credentials = None
        self.propagation_seconds = self.RRP_PROPAGATION_SECONDS

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=120)
        add('credentials', help='RRPproxy credentials INI file.')
        add('propagation_seconds', type=int, default=120, help='Number of secs. to wait for DNS propagation.')
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

    def _txt_record_name(self, record_name):
        return record_name.split('.')[0]

    def _merge_two_dicts(self, x, y):
        z = x.copy()   # start with x's keys and values
        z.update(y)    # modifies z with y's keys and values & returns None
        return z

    def _rrp_api_request(self, command, dnszone, additional_params = {}):
        params_hash = {
            's_login': self.login,
            's_pw': self.password,
            'command': command,
            'dnszone': dnszone
        }

        if self.staging:
            params_hash['s_opmode'] = 'OTE'

        params_hash = self._merge_two_dicts(params_hash, additional_params)
        params = urllib.urlencode(params_hash)
        conn = httplib.HTTPSConnection(self.server)

        if self.staging:
            conn.set_debuglevel(1)

        try:
            conn.request('GET', self.uri + '?' + params)
            return conn.getresponse()
        except httplib.HTTPException as v:
            logger.error(v)

        return None

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        logger.debug('authenticating domain: %s' % domain)
        logger.debug('authenticating record_name: %s' % record_name)
        logger.debug('authenticating record_content: %s' % record_content)
        logger.debug('authenticating record_ttl: %s' % record_ttl)

        self.del_txt_record(domain, record_name, record_content)

        short_record_name = self._txt_record_name(record_name)
        add_params = {'addrr0': '%s %s IN TXT %s' % (short_record_name, record_ttl, record_content)}
        response = self._rrp_api_request('ModifyDNSZone', domain, add_params)
        if response and response.status != 200:
            logger.error('Adding %s to DNSzone %s failed!' % (record_name, domain))
        logger.debug('response.status (ModifyDNSZone): %s' % response.status)
        logger.debug('response.reason (ModifyDNSZone): %s' % response.reason)

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        logger.debug('authenticating domain: %s' % domain)
        logger.debug('authenticating record_name: %s' % record_name)
        logger.debug('authenticating record_content: %s' % record_content)

        response = self._rrp_api_request('QueryDnsZoneRRList', domain)
        logger.debug('response.status: %s' % response.status)
        logger.debug('response.reason: %s' % response.reason)
        if response and response.status == 200:
            data = response.read().decode('utf-8')
            for line in data.split('\n'):
                if 'property[rr]' in line:
                    logger.debug('property[rr] line: %s' % line)
                    short_record_name = self._txt_record_name(record_name)
                    if short_record_name in line:
                        add_params = {'delrr0': re.sub(r'property\[rr\]\[\d+\] = ', '', line)}
                        response = self._rrp_api_request('ModifyDNSZone', domain, add_params)
                        if response and response.status != 200:
                            logger.error('Deleting %s in DNSzone %s failed!' % (short_record_name, domain))
                        logger.debug('response.status (ModifyDNSZone): %s' % response.status)
                        logger.debug('response.reason (ModifyDNSZone): %s' % response.reason)
        else:
            logger.error('HTTP request failed: %s (reason: %s)' % (response.status, response.reason))
