# -*- coding: utf-8 -*-
"""
Handle basic processing of EAPOL frames.
"""

from scapy.layers.eap import EAPOL, EAP
from scapy.layers.tls.record import TLSAlert

from src.utils.tls_helper import get_tls_data


class Supplicant(object):

    """
    Implements a basic 802.1X supplicant.
    """

    def __init__(
            self,
            identity,
            eap_handler
    ):
        super(Supplicant, self).__init__()
        self._identity = identity

        # Create an "EAP handler"
        self._eap_handler = eap_handler

        self._running = True

    @property
    def identity(self):

        """
        Return the supplicant's identity.
        """

        return self._identity

    def __repr__(self):
        return "identity: {}".format(self._identity)

    def stop(self):

        """
        Stop the supplicant.
        """

        self._running = False

    def _process_eapol_frame(self, request):
        eapol_frames = []

        # 1. Check EAPOL type
        if request[EAPOL].type == EAPOL.EAP_PACKET:

            # Process EAP packet
            eap_packet = self._eap_handler.process_eap_packet(request[EAP])
            if eap_packet:
                resp = EAPOL(version=request[EAPOL].version, type=0)/eap_packet
                eapol_frames.append(resp)

                # If the EAP response contains a TLS Alert, add an EAPOL-Logoff
                # frame to the frames that are to be sent.
                tls_data = get_tls_data(eap_packet)
                if tls_data:
                    if tls_data.msg and isinstance(
                            tls_data.msg[0],
                            TLSAlert
                    ):
                        eapol_frames.append(
                            EAPOL(
                                version=resp.version,
                                type=2
                            )
                        )
            else:
                # After having received an EAP-Failure or an EAP-Request
                # matching the current authentication method, send a Logoff
                # message.
                eapol_frames.append(
                    EAPOL
                    (
                        version=request[EAPOL].version,
                        type=2
                    )
                )

        return eapol_frames

    def process_request(self, request):

        """
        Handles an incoming request.
        """

        frames = []
        if self._running and EAPOL in request:
            frames = self._process_eapol_frame(request)

        return frames
