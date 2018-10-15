# -*- coding: utf-8 -*-
"""
The Scanner class handles the "high level" logic, and results processing.
"""

import json

from scapy.layers.eap import EAP, eap_types

import src.core.eap as eap
from src.core import supplicant
from src.core import traffic_handler
from src.utils.tls_helper import TLSVersionGenerator, CipherSuiteGenerator,\
get_tls_data, tls_version_is_valid, cipher_suite_is_valid,\
get_tls_version_name_from_value, get_tls_cipher_suite_name_from_value,\
build_tls_record
from src.utils.common import Observer, FrameReceivedEvent, TestResponseEvent


# Default number of cipher suites sent in the ClientHello
DEFAULT_NUMBER_OF_CIPHER_SUITES = 40


class Scanner(Observer):

    """
    Acts as a "mediator" between the supplicant and the traffic handler.
    """

    def __init__(
            self,
            interface,
            mac_addr,
            identity,
            ssid,
            phase_1_methods=None,
            with_eap_method=None,
            tls_versions=None,
            tls_ciphers=None,
            tls_scan=False,
            tls_min_version=None,
            json_output=None
    ):
        super(Scanner, self).__init__()

        # Create an "EAP handler"
        self._eap_handler = eap.EAPHandler(
            identity,
            tls_scan=tls_scan,
        )
        self._eap_handler.register(self)

        # Create the supplicant
        self._supplicant = supplicant.Supplicant(
            identity,
            self._eap_handler
        )

        if not ssid:
            # Create a "BasicTrafficHandler"
            self._traffic_handler = traffic_handler.BasicTrafficHandler(
                interface,
                mac_addr
            )
        else:
            # Create a "WiFiTrafficHandler"
            self._traffic_handler = traffic_handler.WiFiTrafficHandler(
                interface,
                mac_addr,
                ssid
            )
        self._traffic_handler.register(self)

        # EAP methods
        eap_methods = None
        if phase_1_methods:
            eap_methods = phase_1_methods
        elif with_eap_method:
            eap_methods = [with_eap_method]
        elif tls_scan:
            # If no specific method has been given, but a TLS scan is to be
            # performed, choose EAP-TLS.
            eap_methods = [13]
        self._auth_methods_gen = eap.EAPAuthMethodGenerator(
            phase_1_methods=eap_methods
        )
        self._current_auth_method = self._auth_methods_gen.current_auth_method()

        # Set the authentication method to be used by the EAP handler
        self._eap_handler.current_auth_method = self._current_auth_method

        # Phase 1 test(s) or TLS audit ?
        self._tls_scan = tls_scan

        # TLS versions and cipher suites
        self._tls_versions = tls_versions
        self._tls_version_gen = TLSVersionGenerator(
            versions=tls_versions,
            min_version=tls_min_version
        )
        self._current_tls_version = self._tls_version_gen.current_version()
        self._cs_gen = CipherSuiteGenerator(ciphersuites=tls_ciphers)
        if self._current_tls_version < 0x300:
            self._sslv2_cs_gen = CipherSuiteGenerator(
                sslv2=True,
                ciphersuites=tls_ciphers
            )
        else:
            self._sslv2_cs_gen = None
        self._current_tls_ciphers = None
        if self._tls_versions and 0x0002 in self._tls_versions:
            if self._sslv2_cs_gen:
                self._current_tls_ciphers = self._sslv2_cs_gen.all()
            else:
                # Skip sslv2
                self._tls_version_gen.next()
        if not self._current_tls_ciphers:
            if self._current_tls_version < 0x300:
                self._current_tls_ciphers = self._sslv2_cs_gen.all()
            elif self._cs_gen.remains():
                self._current_tls_ciphers = self._cs_gen.next(
                    number_of_cipher_suites=DEFAULT_NUMBER_OF_CIPHER_SUITES
                )

        # Set the current TLS version and cipher suite to be used
        self._eap_handler.current_tls_version = self._current_tls_version
        self._eap_handler.current_tls_ciphers = self._current_tls_ciphers

        # Output the results in JSON format ?
        self._json_output = json_output

        # Remains True while the scanning process is ongoing
        self._running = False


    def start(self):

        """
        Start the scanner.
        """

        self._running = True
        self._traffic_handler.start()


    def stop(self):

        """
        Stop the scanner.
        """

        self._running = False
        self._supplicant.stop()
        self._traffic_handler.unregister(self)
        self._traffic_handler.stop()


    def notify(self, event):
        request = None

        # Stop processing events that may have been "stacked" once
        # the scanning process has ended.
        if not self._running:
            return

        if isinstance(event, FrameReceivedEvent):
            request = self._traffic_handler.get_incoming_frame()

            # If a request has been received, pass it to the supplicant
            responses = self._supplicant.process_request(request)

            # If the supplicant has generated a response, pass it to the traffic
            # handler
            if responses:
                for response in responses:
                    self._traffic_handler.send_frame(response)

        # Display the test results
        elif isinstance(event, TestResponseEvent):
            test_results = self._process_response(event.test_response)
            for test_result in test_results:
                if not self._json_output:
                    output_mess = "Accepted" if test_result["outcome"] else \
"Rejected"
                    output_mess += "\t"
                    if "auth_method" in test_result.keys():
                        output_mess += "{}\t\t{}".format(
                            test_result["auth_method"],
                            test_result["auth_method_desc"]
                        )
                    elif "tls_version" in test_result.keys():
                        output_mess += "{}\t\t{}".format(
                            test_result["tls_version"],
                            test_result["tls_cipher_suite"]
                        )
                    print(output_mess)
                else:
                    print(json.dumps(test_result))

            # If all tests have been performed, we are done
            if self._test_completed():
                self.stop()

            elif self._tls_scan:
                # Switch to the next TLS version and cipher suite
                self._update_tls_version_and_cipher()
            else:
                self._update_authentication_method()

    def _next_tls_version(self):
        self._current_tls_version = self._tls_version_gen.next()
        return self._current_tls_version

    def _next_tls_ciphers(self):
        if self._current_tls_version == 0x0002:
            self._current_tls_ciphers = self._sslv2_cs_gen.all()
        else:
            self._current_tls_ciphers = self._cs_gen.next(
                number_of_cipher_suites=DEFAULT_NUMBER_OF_CIPHER_SUITES
            )
        return self._current_tls_ciphers

    def _reset_tls_ciphers(self):
        if self._current_tls_version == 0x0002:
            self._sslv2_cs_gen.reset()
            self._current_tls_ciphers = self._sslv2_cs_gen.all()
        else:
            self._cs_gen.reset()
            self._current_tls_ciphers = self._cs_gen.next(
                number_of_cipher_suites=DEFAULT_NUMBER_OF_CIPHER_SUITES
            )

    def _update_tls_version_and_cipher(self):
        # Loop through TLS versions
        if self._current_tls_version == 0x0002:
            if not self._sslv2_cs_gen.remains():
                # All "SSLv2 specific" cipher suites
                # have been tested
                self._current_tls_version = self._next_tls_version()
                self._current_tls_ciphers = self._next_tls_ciphers()
            else:
                self._current_tls_ciphers = self._next_tls_ciphers()
        elif not self._cs_gen.remains():
            if self._tls_version_gen.remains():
                # Test is complete for the current TLS
                # version
                self._reset_tls_ciphers()
                self._tls_version_gen.next()
        elif self._cs_gen.remains():
            # Get the next cipher suite
            self._current_tls_ciphers = self._next_tls_ciphers()

        # Update the current SSL/TLS version
        self._current_tls_version = self._tls_version_gen.current_version()

        # Reflect this change in the EAP handler
        self._eap_handler.current_tls_version = self._current_tls_version
        self._eap_handler.current_tls_ciphers = self._current_tls_ciphers

    def _update_authentication_method(self):
        if self._auth_methods_gen.remains():
            self._current_auth_method = self._auth_methods_gen.next()

        # Set the new authentication method
        self._eap_handler.current_auth_method = self._current_auth_method

    def _test_completed(self):
        test_completed = False

        # TLS audit
        if self._tls_scan:
            if not self._tls_version_gen.remains():
                if self._sslv2_cs_gen:
                    if not self._sslv2_cs_gen.remains() and \
                       not self._cs_gen.remains():
                        test_completed = True
                else:
                    if not self._cs_gen.remains():
                        test_completed = True

        # Authentication method enumeration
        elif not self._auth_methods_gen.remains():
            test_completed = True

        return test_completed

    def _phase_1_test_result(self, outcome):
        result = {
            "auth_method": self._current_auth_method,
            "auth_method_desc": eap_types[self._current_auth_method],
            "outcome": outcome
        }

        return result

    def _tls_test_result(self, outcome, cipher_suite, additional_info=None):
        result = None
        tls_version = None
        tls_cipher_suite = None

        if self._current_tls_version is not None and\
            cipher_suite is not None:
            if tls_version_is_valid(self._current_tls_version):
                tls_version = get_tls_version_name_from_value(
                    self._current_tls_version
                )
            else:
                tls_version = self._current_tls_version
            if cipher_suite_is_valid(cipher_suite):
                tls_cipher_suite = get_tls_cipher_suite_name_from_value(
                    cipher_suite
                )
            else:
                tls_cipher_suite = cipher_suite

            result = {
                "tls_version": tls_version,
                "tls_cipher_suite": tls_cipher_suite,
                "outcome": outcome
            }
            if additional_info:
                for info in additional_info.keys():
                    result[info] = additional_info[info]

        return result

    def _remove_cipher_suite(self, cipher_suite):
        if self._current_tls_version == 0x0002:
            self._sslv2_cs_gen.remove_cipher_suite(cipher_suite)
        else:
            self._cs_gen.remove_cipher_suite(cipher_suite)

    def _process_response(self, eap_packet):
        test_results = []

        # An EAP Request has been received
        if eap_packet.code == EAP.REQUEST:
            # Authentication method enumeration
            if not self._tls_scan:
                test_results.append(self._phase_1_test_result(True))

            else:
                # Process TLS based method
                if eap_packet.type in eap.TLS_BASED_METHODS:
                    # Retrieve the TLS data
                    tls_data = get_tls_data(eap_packet)
                    if tls_data:
                        tls_record = build_tls_record(tls_data)
                        # A ServerHello has been received
                        if tls_record.type == 22 and tls_record.msg and\
                            tls_record.msg[0].msgtype == 2:
                            server_hello = tls_record.msg[0]
                            additional_info = None

                            cipher_suite = server_hello.cipher

                            # Is there a Session ID ?
                            if server_hello.sid:
                                additional_info = {"session_id": True}

                            test_results.append(self._tls_test_result(
                                True,
                                cipher_suite,
                                additional_info
                            ))

                            # Remove the cipher suite
                            self._remove_cipher_suite(cipher_suite)

                        # A TLS Alert message has been received
                        elif tls_record.type == 21:
                            # The server did not accept a single cipher suite.
                            for cipher_suite in self._current_tls_ciphers:
                                test_results.append(self._tls_test_result(
                                    False,
                                    cipher_suite
                                ))

                                # Remove the cipher suite
                                self._remove_cipher_suite(cipher_suite)

        # An EAP Failure has been received
        elif eap_packet.code == EAP.FAILURE:
            # Authentication method enumeration
            if not self._tls_scan:
                test_results.append(self._phase_1_test_result(False))

            # TLS scan
            else:
                # The server did not accept a single cipher suite.
                for cipher_suite in self._current_tls_ciphers:
                    test_results.append(self._tls_test_result(
                        False,
                        cipher_suite
                    ))

                    # Remove the cipher suite
                    self._remove_cipher_suite(cipher_suite)

        return test_results
