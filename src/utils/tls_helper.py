# -*- coding: utf-8 -*-
"""
This module defines generators that are used to perform the TLS scans.
"""

import time
import copy

from collections import OrderedDict

from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS, TLSAlert
from scapy.layers.tls.record import _tls_alert_level, _tls_alert_description
from scapy.layers.tls.record_sslv2 import SSLv2
from scapy.layers.tls.handshake_sslv2 import SSLv2ClientHello
from scapy.layers.tls.crypto.pkcs1 import randstring
from scapy.layers.tls.extensions import TLS_Ext_SessionTicket

from src.utils.log import g_exception_logger


_TLS_VERSIONS_SUPPORTED = {
    "sslv2": 0x0002,
    "sslv3": 0x0300,
    "tls10": 0x0301,
    "tls11": 0x0302,
    "tls12": 0x0303
}

def build_client_hello(tls_version, cipher_suites, session_ticket=None):

    """
    Build a ClientHello with the given TLS version, cipher suite, and optional
    session ticket.
    """

    client_hello_record = None

    # Build TLS ClientHello
    if tls_version > 0x0002:
        extensions = None
        if session_ticket:
            extensions = [TLS_Ext_SessionTicket(ticket=session_ticket)]
        tls_client_hello = TLSClientHello(
            version=tls_version,
            gmt_unix_time=int(time.time()),
            random_bytes=randstring(28),
            sidlen=0,
            ciphers=cipher_suites,
            complen=1,
            ext=extensions
        )
        client_hello_record = TLS(msg=[tls_client_hello])
    else:
        # SSLv2 ClientHello
        sslv2_client_hello = SSLv2ClientHello(
            version=tls_version,
            sidlen=0,
            ciphers=cipher_suites
        )
        client_hello_record = SSLv2(msg=[sslv2_client_hello])

    return client_hello_record


def build_tls_record(tls_data):

    """
    Build a TLS record using the given data.
    """

    return TLS(tls_data)


def build_tls_record_with_message(message):

    """
    Build a TLS record using the given message parameter.
    """

    return TLS(msg=[message])


def build_tls_alert(alert_level, alert_descr):

    """
    Build a TLS Alert using the given Alert level and description.
    """

    return TLSAlert(level=alert_level, descr=alert_descr)


def get_tls_data(incoming_packet):

    """
    Retrieve the TLS data that may be contained in a packet.
    """

    tls_data = None
    if hasattr(incoming_packet, "tls_data"):
        tls_data = copy.deepcopy(incoming_packet.tls_data)
    elif hasattr(incoming_packet, "data"):
        tls_data = copy.deepcopy(incoming_packet.data)
    return tls_data


def get_tls_version_value_from_name(tls_version):

    """
    Return the TLS version number matching a given name ("tls_version").
    """

    tls_version_val = None
    if tls_version in _TLS_VERSIONS_SUPPORTED:
        tls_version_val = _TLS_VERSIONS_SUPPORTED[tls_version]
    return tls_version_val


def tls_version_is_valid(tls_version):

    """
    Return True if the provided TLS version is supported.
    """

    return tls_version in _tls_version.keys()


def cipher_suite_is_valid(cipher_suite):

    """
    Return True if the provided cipher suite exists.
    """

    return cipher_suite in _tls_cipher_suites.keys()


def get_tls_version_name_from_value(tls_version):

    """
    Return the TLS version name from its given value.
    """

    return _tls_version[tls_version]


def get_tls_cipher_suite_name_from_value(cipher_suite):

    """
    Return the TLS cipher suite name from its given value.
    """

    return _tls_cipher_suites[cipher_suite]


def get_tls_alert_level_name_from_value(tls_alert):

    """
    Return the Alert level from its value.
    """

    return _tls_alert_level.get(tls_alert, tls_alert)


def get_tls_alert_descr_from_value(tls_alert_descr):

    """
    Return the Alert description from its value.
    """

    return _tls_alert_description.get(tls_alert_descr, tls_alert_descr)


class CipherSuiteGenerator(object):

    """
    Generator used to iterate over TLS cipher suites.
    """

    def __init__(self, sslv2=False, ciphersuites=None):
        self._add_ciphersuites(sslv2, ciphersuites)
        self._cipher_suites_keys = list(self._cipher_suites.keys())

    def _add_ciphersuites(self, sslv2=False, ciphersuites=None):
        tls_ciphersuites = {}
        candidates = {}
        if ciphersuites and isinstance(ciphersuites, list):
            candidates = {k: v for k, v in _tls_cipher_suites.items() if k in \
ciphersuites}
        else:
            candidates = {k: v for k, v in _tls_cipher_suites.items()}
        if sslv2:
            tls_ciphersuites = {k: v for k, v in candidates.items() \
if v.startswith("SSL_")}
        else:
            tls_ciphersuites = {k: v for k, v in candidates.items() \
if not v.startswith("SSL_") and k != 0x5600 and k != 0x00FF}
        self._cipher_suites = OrderedDict(
            sorted(
                tls_ciphersuites.items(),
                key=lambda x: x[0]
            )
        )

    def __iter__(self):
        for cipher_suite in self._cipher_suites.keys():
            yield self._cipher_suites[cipher_suite]

    def next(self, number_of_cipher_suites=1):

        """
        Return the next n cipher suites.
        """

        last = min(number_of_cipher_suites, len(self._cipher_suites_keys))
        cipher_suites = list(self._cipher_suites_keys[0:last])
        return cipher_suites

    def remains(self):

        """
        Return True if cipher suites remain, False otherwise.
        """

        return len(self._cipher_suites_keys) > 0

    def reset(self):

        """
        Restore the cipher suite list to its original state.
        """

        self._cipher_suites_keys = list(self._cipher_suites.keys())

    def all(self):

        """
        Return a list of all cipher suites.
        """

        return list(self._cipher_suites_keys)

    def remove_cipher_suite(self, cipher_suite):

        """
        Remove a cipher suite from the list.
        """

        try:
            self._cipher_suites_keys.remove(cipher_suite)
        except AttributeError as missing_key:
            g_exception_logger.exception(missing_key)

    def __len__(self):

        """
        Return the number of cipher suites.
        """

        return len(self._cipher_suites)


class TLSVersionGenerator(object):

    """
    Generator used to iterate over existing SSL/TLS versions.
    """

    SSL_TLS_VERSIONS = {
        0: 0x0002, # "SSLv2",
        1: 0x0300, # "SSLv3",
        2: 0x0301, # "TLS 1.0",
        3: 0x0302, # "TLS 1.1",
        4: 0x0303, # "TLS 1.2",
    }

    def __init__(self, versions=None, min_version=None):
        if not versions:
            tls_versions = TLSVersionGenerator.SSL_TLS_VERSIONS
        else:
            tls_versions = {k: v for k, v in TLSVersionGenerator.SSL_TLS_VERSIONS.items() \
                if v in versions}
        self._versions = OrderedDict(tls_versions)
        self._current = 0
        if min_version and min_version in _TLS_VERSIONS_SUPPORTED:
            min_version_val = _TLS_VERSIONS_SUPPORTED[min_version]
            for version in self._versions:
                if self._versions[version] ==\
                    min_version_val:
                    break
                self._current += 1
        if self._current == len(self._versions.keys()):
            # If no specific version was found, start from
            # the first version available
            self._current = 0
        self._has_progressed = False

    def __iter__(self):
        for version in self._versions:
            yield version

    def next(self):

        """
        Return the next SSL/TLS version, if any.
        """

        if self._current < len(self._versions.keys()) - 1:
            self._current += 1
        version = self._versions[list(self._versions.keys())[self._current]]
        self._has_progressed = True
        return version

    def current_version(self):

        """
        Return the current SSL/TLS version.
        """

        self._has_progressed = True
        return self._versions[list(self._versions.keys())[self._current]]

    def remains(self):

        """
        Return the number of remaining SSL/TLS versions
        """

        remains = False
        if not self._has_progressed:
            remains = True
        else:
            remains = len(self._versions.keys()) - 1 - self._current > 0
        return remains

    def __len__(self):
        return len(self._versions)
