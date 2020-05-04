#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import unicode_literals

import dns.resolver
import dns.zone
import logging
import os
import time
import requests
import sys
import socket

from typing import List

from certbot_dns_hetzner.hetzner_client import _HetznerClient, HETZNER_API_ENDPOINT, _NotAuthorizedException, \
    _MalformedResponseException, _ZoneNotFoundException, _RecordNotFoundException

LOGGER = logging.getLogger(__name__)

ACME_CHALLENGE = '_acme-challenge'

TTL = 3600


class HetznerProvider(_HetznerClient):
    """
    Implements the Hetzner DNS Provider
    Makes use of the newer 2020 Hetzner DNS API, as implemented by the python package certbot_dns_hetzner.
    """

    def __init__(self):
        super(HetznerProvider, self).__init__(HetznerProvider.get_token_from_environment())

    def set_challenge(self, domain: str, challenge_value: str, wait_propagate: bool):
        LOGGER.info(f'Hetzner => Deploying Challenge {challenge_value} to domain {domain}')
        self.add_record(domain, 'TXT', ACME_CHALLENGE, challenge_value, TTL)
        if wait_propagate:
            self.wait_propagated(domain, challenge_value)

    def delete_challenge(self, domain: str):
        LOGGER.info(f'Hetzner => Clearing Challenge from domain {domain}')
        while True:
            try:
                self.delete_record_by_name(domain, ACME_CHALLENGE)
            except _RecordNotFoundException:
                return

    def wait_propagated(self, domain: str, value: str):
        fqdn = HetznerProvider.domain_validation_fqdn(domain)
        name_servers = self._get_nameservers_by_domain(domain)
        HetznerProvider._propagated_record('TXT', fqdn, f'"{value}"', name_servers)

    def _get_nameservers_by_domain(self, domain) -> List[str]:
        domain_tokens = domain.split('.')
        zones_response = requests.get(url=f"{HETZNER_API_ENDPOINT}/zones", headers=self._headers)
        if zones_response.status_code == 401:
            raise _NotAuthorizedException()
        try:
            zones = zones_response.json()['zones']
            for zone in zones:
                zone_name_tokens = zone['name'].split('.')
                # take sld and tld to match zones
                if zone_name_tokens[-1] == domain_tokens[-1] and zone_name_tokens[-2] == domain_tokens[-2]:
                    return zone['ns']
        except (KeyError, UnicodeDecodeError, ValueError) as exception:
            raise _MalformedResponseException(exception)
        raise _ZoneNotFoundException(domain)

    @staticmethod
    def get_token_from_environment():
        token = os.environ.get('HETZNER_AUTH_TOKEN')
        if token == '' or token is None:
            LOGGER.error('Hetzner => HETZNER_AUTH_TOKEN must be provided!')
            raise AssertionError
        LOGGER.debug('Hetzner => HETZNER_AUTH_TOKEN = %s', token)
        return token

    @staticmethod
    def domain_validation_fqdn(domain: str):
        return f'{ACME_CHALLENGE}.{domain}'

    @staticmethod
    def _propagated_record(rdtype, name, content, nameservers=None):
        """
        If the publicly propagation check should be done, waits until the domain nameservers
        responses with the propagated record type, name & content and returns a boolean,
        if the publicly propagation was successful or not.
        """
        nameserver_ips = None
        if nameservers is not None:
            nameserver_ips = [socket.gethostbyname(ns) for ns in nameservers]
        latency = 30
        retry, max_retry = 0, 20
        LOGGER.info('Hetzner => Waiting for Records to be propagated ...')
        while retry < max_retry:
            for rdata in HetznerProvider._dns_lookup(name, rdtype, nameserver_ips):
                if content == rdata.to_text():
                    LOGGER.info('Hetzner => Record %s has %s %s', name, rdtype, content)
                    return True
            retry += 1
            retry_log = (', retry ({}/{}) in {}s...'.format((retry + 1), max_retry, latency)
                         if retry < max_retry else '')
            LOGGER.info('Hetzner => Record is not propagated%s', retry_log)
            time.sleep(latency)
        return False

    @staticmethod
    def _dns_lookup(name, rdtype, nameservers=None):
        """
        Looks on specified or default system domain nameservers to resolve record type
        & name and returns record set. The record set is empty if no propagated
        record found.
        """
        LOGGER.debug(f'DNS Lookup => {name} {rdtype} {nameservers}')
        rrset = dns.rrset.from_text(name, 0, 1, rdtype)
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 1
            if nameservers:
                resolver.nameservers = nameservers
            rrset = resolver.query(name, rdtype)
            for rdata in rrset:
                LOGGER.debug('DNS Lookup => %s %s %s %s',
                             rrset.name.to_text(), dns.rdataclass.to_text(rrset.rdclass),
                             dns.rdatatype.to_text(rrset.rdtype), rdata.to_text())
        except dns.exception.DNSException as error:
            LOGGER.debug('DNS Lookup => %s', error)
        return rrset


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    LOGGER.debug('HETZNER => Deploy SSL certificate: %s', fullchain_pem)
    LOGGER.debug('HETZNER => Deploy SSL certificate key: %s', privkey_pem)


def unchanged_cert(args):
    pass


def deploy_challenge(args):
    provider = HetznerProvider()
    for idx in range(0, len(args), 3):
        wait_for_propagate = idx >= (len(args) - 3)
        challenge_value = args[(idx + 2)]
        provider.set_challenge(args[idx], challenge_value, wait_for_propagate)
    LOGGER.info('HETZNER => All challenges deployed')


def clean_challenge(args):
    provider = HetznerProvider()
    for idx in range(0, len(args), 3):
        provider.delete_challenge(args[idx])
    LOGGER.info('HETZNER => All challenges cleaned')


def invalid_challenge(args):
    domain, result = args
    LOGGER.debug('HETZNER => Invalid challenge for %s: %s', domain, result)
    return


def startup_hook(args):
    return


def exit_hook(args):
    return


def main(argv):
    log_level = os.environ.get('HETZNER_LOG_LEVEL', 'INFO')
    if log_level not in ('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET'):
        logging.basicConfig(stream=sys.stdout, level='ERROR', format='%(message)s')
        LOGGER.error('Hetzner => HETZNER_LOG_LEVEL is invalid: \'%s\' (choose from '
                     '\'CRITICAL\', \'ERROR\', \'WARNING\', \'INFO\', \'DEBUG\' or '
                     '\'NOTSET\')', log_level)
        raise AssertionError
    logging.basicConfig(stream=sys.stdout, level=log_level, format='%(message)s')
    ops = {
        'deploy_cert': deploy_cert,
        'unchanged_cert': unchanged_cert,
        'deploy_challenge': deploy_challenge,
        'clean_challenge': clean_challenge,
        'invalid_challenge': invalid_challenge,
        'startup_hook': startup_hook,
        'exit_hook': exit_hook
    }
    if argv[0] in ops:
        LOGGER.info(' + Hetzner hook executing %s...', argv[0])
        ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
