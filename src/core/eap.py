# -*- coding: utf-8 -*-
"""
IEEE 802.1X supplicant - EAP "processor" ("higher" layer)
"""

from scapy.layers.eap import EAP, EAP_TLS, EAP_TTLS

from src.utils.tls_helper import build_client_hello, get_tls_data,\
build_tls_record, build_tls_record_with_message, build_tls_alert
from src.utils.common import Observable, TestResponseEvent


# List of TLS-based EAP authentication methods
TLS_BASED_METHODS = [
    13, # EAP-TLS
    21, # EAP-TTLS
    25  # PEAP
]

TLS_BASED_METHODS_BY_NAME = {
    "tls": 13,
    "ttls": 21,
    "peap": 25
}

class EAPAuthMethodGenerator(object):

    """
    Allows to iterate over the EAP authentication methods.
    """

    def __init__(self, phase_1_methods=None):
        #
        # Add registered EAP methods
        # http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml
        # Skip method types 7 and 8. These are marked as "Allocated", but are
        # not actual EAP authentication methods. Skip method type 20
        # (Unassigned) as well.
        #

        # First auth. method: EAP-MD5 (4)
        auth_methods = [x for x in range(4, 7)]
        for method in range(9, 20):
            auth_methods.append(method)
        for method in range(21, 56):
            auth_methods.append(method)
        auth_methods.append(255) # Add "Experimental"
        if phase_1_methods:
            self._auth_methods = []
            for method in phase_1_methods:
                if method in auth_methods:
                    self._auth_methods.append(method)
        else:
            self._auth_methods = auth_methods
        self._current = 0

    def __iter__(self):
        for method in self._auth_methods:
            yield method

    def next(self):

        """
        Return the next EAP authentication method.
        """

        if self._current < len(self._auth_methods) - 1:
            self._current += 1
        method = self._auth_methods[self._current]
        return method

    def current_auth_method(self):

        """
        Return the current EAP authentication method.
        """

        return self._auth_methods[self._current]

    def remains(self):

        """
        Return the number of remaining EAP authentication methods.
        """

        return len(self._auth_methods) - self._current - 1 > 0

    def __len__(self):

        """
        Return the number of authentication methods.
        """

        return len(self._auth_methods)


def _build_eap_response_probe(eap_method, packet_id, client_hello_record, version=None):

    """
    Build an EAP response packet for a given method, packet Id., version, using
    the provided Client Hello record.
    """

    eap_response = None

    if eap_method == 13:
        # EAP-TLS
        eap_response = EAP_TLS(
            code=EAP.RESPONSE,
            id=packet_id,
            tls_data=client_hello_record
        )

    elif eap_method == 21:
        # EAP-TTLS
        eap_response = EAP_TTLS(
            code=EAP.RESPONSE,
            id=packet_id,
            data=client_hello_record
        )
        if version:
            eap_response.version = version

    elif eap_method == 25:
        # PEAP
        eap_response = EAP_TTLS(
            code=EAP.RESPONSE,
            id=packet_id,
            data=client_hello_record
        )
        eap_response.type = 25
        if version:
            eap_response.version = version

    return eap_response


def _build_legacy_nak(request_id, desired_auth_type):

    """
    Build a Legacy Nak packet, in order to ask for a specific authentication
    method.
    """

    eap_response = EAP(
        code=EAP.RESPONSE,
        id=request_id,
        type=3,
        desired_auth_types=[desired_auth_type]
    )

    return eap_response


class EAPHandler(Observable):

    """
    Implement the layer that handles EAP packets.
    """

    def __init__(
            self,
            identity,
            tls_scan=False
    ):
        super(EAPHandler, self).__init__()

        self._identity = identity
        self._tls_scan = tls_scan
        self._current_auth_method = None
        self._current_tls_version = None
        self._current_tls_ciphers = None
        self._auth_process_in_progress = False

    @property
    def current_auth_method(self):

        """
        Return the current authentication method.
        """

        return self._current_auth_method

    @current_auth_method.setter
    def current_auth_method(self, auth_method):

        """
        Set the current authentication method.
        """

        self._current_auth_method = auth_method

    @property
    def current_tls_version(self):

        """
        Return the current TLS version.
        """

        return self._current_tls_version

    @current_tls_version.setter
    def current_tls_version(self, version):

        """
        Set the current TLS ciphers.
        """

        self._current_tls_version = version

    @property
    def current_tls_ciphers(self):

        """
        Return the current TLS ciphers.
        """

        return self._current_tls_ciphers

    @current_tls_ciphers.setter
    def current_tls_ciphers(self, cipher_suites):
        self._current_tls_ciphers = cipher_suites

    def _process_request(self, eap_request):
        eap_response = None
        is_test_response = False

        # If the authentication method is not the expected one, send a
        # Legacy Nak asking for the specified EAP method.
        if eap_request.type != self._current_auth_method:
            desired_auth_type_ = self._current_auth_method
            eap_response = _build_legacy_nak(
                eap_request.id,
                desired_auth_type_
            )
        else:
            # We should have received a request with the specified
            # authentication method
            # At this point, we can assume that the RADIUS server supports
            # the current authentication method. An EAPOL-Logoff should be
            # sent by the supplicant.
            is_test_response = True

        return eap_response, is_test_response

    def _process_tls_request(self, eap_request):
        eap_response = None
        is_test_response = False

        if hasattr(eap_request, "S") and eap_request.S:
            tls_version = self._current_tls_version
            cipher_suites = self._current_tls_ciphers

            #
            # EAP-Request / Starting TLS-based authentication
            #

            # Build ClientHello
            client_hello_record = build_client_hello(
                tls_version,
                cipher_suites
            )

            version_ = None
            if hasattr(eap_request, "version"):
                version_ = eap_request.version

            # Build the response packet
            eap_response = _build_eap_response_probe(
                self._current_auth_method or 13,
                eap_request.id,
                client_hello_record,
                version=version_
            )

        else:
            # The authentication process has already started
            # Retrieve the TLS data, if any
            tls_data = get_tls_data(eap_request)
            if tls_data:
                tls_record = build_tls_record(tls_data)

                # Handle Server Hello
                if tls_record.type == 22 and tls_record.msg and\
tls_record.msg[0].msgtype == 2:
                    # Send TLS Alert message to stop the process
                    eap_response = EAP_TLS(
                        code=EAP.RESPONSE,
                        id=eap_request.id,
                        tls_data=build_tls_record_with_message(
                            build_tls_alert(1, 0)
                        )
                    )

                # TLS Alerts are handled in scanner.py

                # At this point, the received EAP packet should be a valid
                # response to the probe that was sent
                is_test_response = True

        return eap_response, is_test_response

    def _process_eap_request(self, eap_request):

        """
        Process incoming EAP requests.
        """

        eap_response = None
        test_response = False

        # Request-Identity
        if eap_request.type == 1:
            eap_response = EAP(
                code=EAP.RESPONSE,
                id=eap_request.id,
                type=1,
                identity=self._identity
            )

        elif eap_request.type > 3:
            # At this point, a new authentication process has started
            self._auth_process_in_progress = True

            # Process phase 1 tests
            if not self._tls_scan:
                eap_response, test_response =\
                    self._process_request(eap_request)

            # Process TLS based method
            elif eap_request.type in TLS_BASED_METHODS:
                # We're expecting a Request with a type matching a TLS-based
                # authentication method. If the authentication method is not
                # the expected one, send a Legacy Nak asking for EAP-TLS (or
                # the specified EAP method).
                if eap_request.type != self._current_auth_method:
                    desired_auth_type_ = self._current_auth_method or 13
                    eap_response = _build_legacy_nak(
                        eap_request.id,
                        desired_auth_type_
                    )
                else:
                    eap_response, test_response =\
                        self._process_tls_request(eap_request)

            else:
                # If the authentication method is not the expected one,
                # send a Legacy Nak asking for EAP-TLS (or the specified
                # EAP method).
                if eap_request.type != self._current_auth_method:
                    desired_auth_type_ = self._current_auth_method or 13
                    eap_response = _build_legacy_nak(
                        eap_request.id,
                        desired_auth_type_
                    )

        return eap_response, test_response

    def _process_eap_failure(self):

        """
        Process incoming EAP Failure messages.
        """

        test_response = False

        if self._auth_process_in_progress:
            test_response = True

        return test_response

    def process_eap_packet(self, incoming_packet):

        """
        Process received EAP packets. The input must be a valid EAP packet.
        """

        eap_packet = None
        test_response = False

        #
        # EAP-Request
        #

        if incoming_packet.code == EAP.REQUEST:
            eap_packet, test_response =\
                self._process_eap_request(incoming_packet)

        #
        # EAP-Failure
        #

        elif incoming_packet.code == EAP.FAILURE:
            test_response = self._process_eap_failure()

        if test_response:
            # Fire TestResponseEvent
            event = TestResponseEvent(
                source=self.__class__.__name__,
                test_response=incoming_packet,
            )
            self.notify_observers(event)
            self._auth_process_in_progress = False

        return eap_packet
