# -*- coding: utf-8 -*-
"""
Defines classes used to send and receive EAPOL frames.
"""

from __future__ import print_function

import queue
import select
import socket
import binascii
import time
import struct

from abc import ABCMeta, abstractmethod

from scapy.layers.l2 import Ether
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Elt,\
Dot11EltRSN, Dot11EltMicrosoftWPA, Dot11Auth, Dot11Deauth,\
Dot11AssoResp, Dot11Disas
from scapy.layers.eap import EAPOL, EAP
from scapy.arch.linux import L2ListenSocket
from scapy.sendrecv import sendp

from pyroute2 import IW
from pyroute2.netlink.exceptions import NetlinkError

from src.utils import common
from src.utils.utils import ETH_P_ALL, MONITOR_INTERFACE_NAME,\
IEEE_802_1X_ETHERTYPE, PAE_GROUP_ADDR,\
get_interface_index, set_interface_operstate
from src.utils.log import g_traffic_logger, g_default_logger,\
g_exception_logger


class TrafficHandler(common.Observable):

    """
    Abstract class from which all traffic handler should inherit (currently,
    there is only the BasicTrafficHandler class).
    """

    __metaclass__ = ABCMeta

    def __init__(self, iface, mac_addr):
        super(TrafficHandler, self).__init__()
        self._iface = iface
        self._iface_index = get_interface_index(iface)
        self._local_mac_addr = mac_addr
        self._socket = None
        self._received_frames = queue.LifoQueue(maxsize=10)
        self._running = False
        self._eapol_version = 1

    @abstractmethod
    def get_incoming_frame(self):

        """
        Process a frame sent by the authenticator.
        """

        return

    @abstractmethod
    def send_frame(self, eapol_frame):

        """
        Sends an EAPOL frame to the authenticator.
        """

        pass


class BasicTrafficHandler(TrafficHandler):

    """
    Handle traffic received on a local interface.
    """

    def __init__(self, iface, mac_addr):
        super(BasicTrafficHandler, self).__init__(iface, mac_addr)

    def _handle_received_frame(self, frame):

        """
        If a frame carrying an EAP packet has been received, add it to the
        queue and notify the observers.
        """

        if EAP in frame:
            g_traffic_logger.info("\t<- %s", frame[EAP].summary())
            self._received_frames.put(frame)
            event = common.FrameReceivedEvent()
            self.notify_observers(event)

    def get_incoming_frame(self):

        """
        Retrieves the last frame received.
        """

        return self._received_frames.get()

    def send_frame(self, eapol_frame):

        # Prevent frames from being sent once the handler has been stopped
        # (this may happen when ending the scanning process, when there are
        # still events in the stack).
        if not self._running:
            return

        frame = Ether(
            dst=PAE_GROUP_ADDR,
            src=self._local_mac_addr,
            type=IEEE_802_1X_ETHERTYPE)/eapol_frame
        if EAP in frame:
            g_traffic_logger.info("%s ->", frame[EAP].summary())
        elif EAPOL in frame:
            g_traffic_logger.info("%s ->", frame[EAPOL].summary())
        sendp(frame, iface=self._iface, verbose=False)

    def start(self):

        """
        Start listening for incoming frames.
        """

        resume_scanning = True
        self._running = True

        try:
            self._socket = L2ListenSocket(iface=self._iface)
        except OSError as err:
            g_default_logger.error("Cannot listen on the provided interface \
(%s).", self._iface)
            g_exception_logger.exception(err)

        while self._running:
            try:
                read, _, __ = select.select([self._socket], [], [], 0.05)
                if read:
                    frame = self._socket.recv()
                    if frame.src != self._local_mac_addr:
                        self._handle_received_frame(frame)

                if resume_scanning:
                    # Send an EAPOL-Start frame to try to start the authentication
                    # process.
                    eapol_start_frame = EAPOL(version=self._eapol_version, type=1)
                    self.send_frame(eapol_start_frame)
                    resume_scanning = False

            except socket.error as err_mess:
                g_exception_logger.exception(err_mess)
                self._running = False

            except KeyboardInterrupt as keyboard_interrupt:
                # This exception should be caught (ra.py)
                raise keyboard_interrupt

    def stop(self):

        """
        Stops listening.
        """

        if self._socket and not self._socket.closed:
            self._socket.close()
        # Set interface operational state to "DOWN", and linkmode to default
        set_interface_operstate(
            self._iface_index,
            0,
            "UP"
        )
        self._running = False


class WiFiTrafficHandler(TrafficHandler):

    """
    Handle traffic received on a local wireless interface.
    """

    # Authentication status
    AUTH_STATUS_NOT_AUTHENTICATED = 0
    AUTH_STATUS_AUTHENTICATING = 1
    AUTH_STATUS_AUTHENTICATED = 2

    # Association status
    ASSO_STATUS_NOT_ASSOCIATED = 0
    ASSO_STATUS_ASSOCIATING = 1
    ASSO_STATUS_ASSOCIATED = 2

    def __init__(self, iface, mac_addr, ssid):
        super(WiFiTrafficHandler, self).__init__(iface, mac_addr)
        self._ssid = ssid
        self._monitor_socket = None
        self._bssid = None
        self._frequency = None
        self._rsn = None
        self._ms_wpa_ie = None
        self._ssid_info_learned_in_presp = False
        self._authentication_status = \
            WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED
        self._association_status = \
            WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED
        self._previously_associated = False
        self._link_ready = False

    def associated(self):

        """
        Return True if the station is associated with an AP.
        """

        return self._association_status == \
            WiFiTrafficHandler.ASSO_STATUS_ASSOCIATED

    def authenticated(self):

        """
        Return True if the station is authenticated with an AP.
        """

        return self._authentication_status == \
            WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATED

    def _has_ssid_info(self):
        has_ssid_info = False

        if self._bssid and self._frequency and (self._rsn or self._ms_wpa_ie):
            has_ssid_info = True

        return has_ssid_info

    def get_incoming_frame(self):

        """
        Retrieves the last frame received.
        """

        return self._received_frames.get()


    def _scan(self):

        """
        Perform a scan and retrieve information related to the target SSID.
        """

        err_occurred = False
        bss_status_attr = None
        found = False
        rsn_ie_data = None
        vendor_ie_data = None

        try:
            with IW() as iw: # pylint: disable-msg=C0103
                scan_results = iw.scan(
                    self._iface_index,
                    [self._ssid],
                    flush_cache=True
                )
                bss_attr = None
                for result in scan_results:
                    bss_attr = result.get_attr('NL80211_ATTR_BSS')
                    if bss_attr is not None:
                        attrs = bss_attr["attrs"]
                        bss_ie = [x[1] for x in attrs if x[0] == \
                            "NL80211_BSS_INFORMATION_ELEMENTS"]
                        if bss_ie:
                            # Get SSID
                            ssid = bss_ie[0].get("SSID", None)
                            if ssid.decode("ascii") == self._ssid:
                                # Get RSN IEs
                                rsn_ie_data = bss_ie[0].get("RSN", None)
                                vendor_ie_data = bss_ie[0].get("VENDOR", None)
                                found = True
                                break
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
            err_occurred = True

        if found:
            self._bssid = bss_attr.get_attr("NL80211_BSS_BSSID")
            self._frequency = bss_attr.get_attr("NL80211_BSS_FREQUENCY")
            from_presp = bss_attr.get_attr('NL80211_BSS_PRESP_DATA')
            self._ssid_info_learned_in_presp = True if from_presp else False
            bss_status_attr = bss_attr.get_attr("NL80211_BSS_STATUS")

        return err_occurred, bss_status_attr, rsn_ie_data, vendor_ie_data


    def _authenticate(self):

        """
        Send an Authentication frame.
        """

        err_occurred = False

        try:
            with IW() as iw: # pylint: disable-msg=C0103
                iw.authenticate(
                    self._iface_index,
                    self._bssid,
                    self._ssid,
                    self._frequency
                )
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
            err_occurred = True

        return err_occurred


    def _deauthenticate(self):

        """
        Send a Deauthentication frame.
        """

        err_occurred = False

        try:
            with IW() as iw: # pylint: disable-msg=C0103
                iw.deauthenticate(
                    self._iface_index,
                    self._bssid,
                    reason_code=0x01
                )
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
            err_occurred = True

        return err_occurred


    def _associate(self):

        """
        Send an Association request.
        """

        err_occurred = False

        # Prepare the RSN IEs
        information_elements = bytes()
        if self._rsn:
            information_elements = bytes(self._rsn)

        if self._ms_wpa_ie:
            information_elements += bytes(self._ms_wpa_ie)

        try:
            with IW() as iw: # pylint: disable-msg=C0103
                g_default_logger.info("Trying to associate ...")
                iw.associate(
                    self._iface_index,
                    self._bssid,
                    self._ssid,
                    self._frequency,
                    info_elements=information_elements
                )
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
            err_occurred = True

            # At this point, the association process probably failed
            while err_occurred:
                time.sleep(0.05)
                try:
                    with IW() as iw: # pylint: disable-msg=C0103
                        g_default_logger.info("Trying to associate ...")
                        iw.associate(
                            self._iface_index,
                            self._bssid,
                            self._ssid,
                            self._frequency,
                            info_elements=information_elements
                        )
                        err_occurred = False
                except NetlinkError as netlink_err_:
                    g_exception_logger.exception(netlink_err_)
                    err_occurred = True

        return err_occurred


    def _disassociate(self):

        """
        Send a Disassociation request.
        """

        err_occurred = False

        try:
            with IW() as iw: # pylint: disable-msg=C0103
                iw.disassociate(
                    self._iface_index,
                    self._bssid,
                    reason_code=0x08
                )
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
            err_occurred = True

        return err_occurred


    @staticmethod
    def _check_akm_suite(rsn_info_element):
        wpa_akm_found = False

        if rsn_info_element.nb_akm_suites > 0:
            for akm_suite in rsn_info_element.akm_suites:
                if akm_suite.suite == 0x01:
                    wpa_akm_found = True

        return wpa_akm_found

    def _expected_akm_found(self):
        expected_akm_found = False

        if self._rsn:
            # Check the RSN IE
            expected_akm_found = WiFiTrafficHandler._check_akm_suite(self._rsn)

        if not expected_akm_found and self._ms_wpa_ie:
            # Check the vendor specific Microsoft WPA IE
            expected_akm_found = WiFiTrafficHandler._check_akm_suite(
                self._ms_wpa_ie
            )

        return expected_akm_found

    def _parse_ies(self, info_elements):
        ssid_found = False

        for info_el in info_elements:
            if info_el.ID == 0:
                # SSID
                ssid_str = info_el.info.decode("utf-8")
                if ssid_str == self._ssid:
                    ssid_found = True
                else:
                    break
            elif info_el.ID == 48:
                # RSN
                self._rsn = info_el
            elif info_el.ID == 221:
                # Vendor Specific - Microsoft WPA RSN ?
                if isinstance(info_el, Dot11EltMicrosoftWPA):
                    self._ms_wpa_ie = info_el

        return ssid_found

    def _prepare(self):
        err = None
        bss_status_attr = None
        rsn_ie_data = None
        vendor_ie_data = None

        # Scan first
        try:
            err, bss_status_attr, rsn_ie_data, vendor_ie_data = self._scan()
            while err or (not rsn_ie_data and not vendor_ie_data):
                time.sleep(0.5)
                g_default_logger.info("Looking for %s ...", self._ssid)
                err, bss_status_attr, rsn_ie_data, vendor_ie_data = \
                    self._scan()
        except KeyboardInterrupt as keyboard_interrupt:
            # This exception should be caught (ra.py)
            raise keyboard_interrupt

        if bss_status_attr:
            if bss_status_attr == 0:
                # Send a Deauthentication frame
                self._authentication_status = \
                    WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED
                self._deauthenticate()
            elif bss_status_attr == 1:
                # Send a Disassociation frame
                self._association_status = \
                    WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED
                self._disassociate()

        if rsn_ie_data:
            packed_ies = struct.pack("!B", 48) + \
                struct.pack("!B", len(rsn_ie_data)) + rsn_ie_data
            info_elements = Dot11Elt(packed_ies)
            if Dot11EltRSN in info_elements:
                self._rsn = info_elements[Dot11EltRSN]

        if vendor_ie_data:
            for vendor_ie in vendor_ie_data:
                packed_ies = struct.pack("!B", 221) + \
                    struct.pack("!B", len(vendor_ie)) + vendor_ie
                info_element = Dot11Elt(packed_ies)
                if isinstance(info_element, Dot11EltMicrosoftWPA):
                    self._ms_wpa_ie = info_element[Dot11EltMicrosoftWPA]

        if not self._expected_akm_found():
            g_default_logger.warning("(%s) AKM is not IEEE 802.1X / PMKSA \
caching.", self._ssid)


    def _clear_ssid_info(self):
        self._bssid = None
        self._frequency = None
        self._rsn = None
        self._ms_wpa_ie = None


    def _handle_received_frame(self, frame):

        """
        If a frame carrying an EAP packet has been received, add it to the
        queue and notify the observers.
        Handle 802.11 authentication and association.
        """

        #
        # 802.11
        #

        dot11_frame = frame[Dot11]

        # Is it a Probe Response ?
        if frame[Dot11].type == 0b00 and frame[Dot11].subtype == 5:
            if self._authentication_status == \
                WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATED:
                # If we're already authenticated, there is no need to process
                # a Probe Response.
                return
            # Look for the SSID
            if Dot11Elt in frame[Dot11]:
                data = frame[Dot11][Dot11Elt]
                ssid_found = self._parse_ies(data)
                if ssid_found and self._authentication_status == \
                    WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED:
                    if not self._authentication_status == \
                        WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATING:
                        # Attempt to authenticate
                        self._authentication_status = \
                            WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATING
                        if self._authenticate():
                            # At this point, the authentication process probably
                            # failed
                            g_default_logger.warning("Could not authenticate.")
                            self._authentication_status = \
                                WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED

        # Is it a Deauthentication frame ?
        elif Dot11Deauth in dot11_frame:
            g_default_logger.warning("Deauthenticated.\tBSSID: %s", self._bssid)
            self._authentication_status = \
                WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED

        elif Dot11Disas in dot11_frame:
            g_default_logger.warning(
                "Disassociated.\tSSID: %s, BSSID: %s",
                self._ssid,
                self._bssid
            )
            self._association_status = \
                WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED
            # Consider we're not authenticated anymore, as well
            self._authentication_status = \
                WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED
            self._clear_ssid_info()

        elif Dot11Auth in dot11_frame:
            if self._authentication_status == \
                WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATING:
                if dot11_frame.algo == 0 and dot11_frame.status == 0:
                    g_default_logger.info(
                        "Authenticated.\tBSSID: %s",
                        self._bssid
                    )
                    self._authentication_status = \
                            WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATED

                    # Attempt to associate
                    self._association_status =\
                        WiFiTrafficHandler.ASSO_STATUS_ASSOCIATING
                    if self._associate():
                        # At this point, the association process probably
                        # failed
                        g_default_logger.warning(
                            "Could not associate with %s",
                            self._bssid
                        )
                        self._association_status = \
                            WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED

        elif Dot11AssoResp in dot11_frame:
            if dot11_frame.status == 0:
                # The association succeeded
                g_default_logger.info(
                    "Associated.\tSSID: %s, BSSID: %s",
                    self._ssid,
                    self._bssid
                )
                self._association_status = \
                    WiFiTrafficHandler.ASSO_STATUS_ASSOCIATED
                self._previously_associated = True

                # Resume the scanning process, if it was interrupted
                eapol_start_frame = EAPOL(version=self._eapol_version, type=1)
                self.send_frame(eapol_start_frame)

        #
        # EAPOL / EAP
        #

        elif EAPOL in frame:
            if EAP in frame:
                g_traffic_logger.info("\t<- %s", frame[EAP].summary())
                try:
                    self._received_frames.put(frame, block=False)
                except queue.Full:
                    # The authentication process is made of ordered request /
                    # response exchanges. This should not happen ...
                    while not self._received_frames.empty():
                        self._received_frames.get()
                    self._received_frames.put(frame, block=False)

                event = common.FrameReceivedEvent()
                self.notify_observers(event)

            # Use the same EAPOL version
            self._eapol_version = frame[EAPOL].version


    def send_frame(self, eapol_frame):

        """
        Send an EAPOL frame.
        """

        # Prevent frames from being sent once the handler has been stopped
        # (this may happen when ending the scanning process, when there are
        # still events in the stack).
        if not self._running:
            return

        if EAP in eapol_frame:
            g_traffic_logger.info("%s ->", eapol_frame[EAP].summary())
        elif EAPOL in eapol_frame:
            g_traffic_logger.info("%s ->", eapol_frame[EAPOL].summary())
        else:
            g_traffic_logger.info(eapol_frame.summary())

        if self._bssid:
            dest_addr = self._bssid.replace(':', '')
            packed_dest_addr = binascii.unhexlify(dest_addr)
            self._socket.sendto(
                bytes(eapol_frame),
                (
                    self._iface,
                    IEEE_802_1X_ETHERTYPE,
                    0,
                    0,
                    packed_dest_addr
                )
            )
        else:
            if EAP in eapol_frame:
                g_default_logger.warning("Could not send frame:  %s", \
eapol_frame[EAP].summary())
            elif EAPOL in eapol_frame:
                g_default_logger.warning("Could not send frame:  %s", \
eapol_frame[EAPOL].summary())
            else:
                g_default_logger.warning("Could not send frame:  %s", \
eapol_frame.summary())

    def _detect_association_loss(self):
        association_loss = False

        if self._previously_associated:
            with IW() as iw: # pylint: disable-msg=C0103
                data = iw.get_stations(self._iface_index)
            if data:
                for attr in data[0]["attrs"]:
                    if attr[0] == 'NL80211_ATTR_STA_INFO':
                        for sta_info in attr[1]["attrs"]:
                            if sta_info[0] == 'NL80211_STA_INFO_STA_FLAGS':
                                if not sta_info[1]["AUTHENTICATED"]:
                                    association_loss = True
                                    self._authentication_status = \
                                        WiFiTrafficHandler.\
AUTH_STATUS_NOT_AUTHENTICATED
                                if not sta_info[1]["ASSOCIATED"]:
                                    association_loss = True
                                    self._association_status = \
                                        WiFiTrafficHandler.\
ASSO_STATUS_NOT_ASSOCIATED

            else:
                # Assume that we're no longer associated
                association_loss = True
                self._association_status = \
                    WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED
                self._authentication_status = \
                    WiFiTrafficHandler.AUTH_STATUS_NOT_AUTHENTICATED

        return association_loss


    def start(self):

        """
        Start listening for incoming frames.
        """

        # Open a socket that will be used to send frames
        self._socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_DGRAM,
            socket.htons(ETH_P_ALL)
        )

        # Open a socket on the monitor interface
        self._monitor_socket = L2ListenSocket(iface=MONITOR_INTERFACE_NAME)

        i = 0
        self._running = True
        while self._running:
            try:
                read, _, __ = select.select([self._monitor_socket.fileno()], [], [], 0.05)
                if read:
                    data_ = self._monitor_socket.recv(4096)
                    frame = RadioTap(data_)

                    if Dot11 in frame and\
                        frame[Dot11].addr2 != self._local_mac_addr:
                        self._handle_received_frame(frame)

                # Every 2.5+ seconds, try to detect any association loss
                if not i % 50:
                    association_loss = self._detect_association_loss()
                    if association_loss:
                        g_default_logger.info("Not associated with %s \
anymore.", self._bssid)
                        self._clear_ssid_info()
                    i = 0

                # If we're not associated, trigger a new scan in order to
                # retrieve necessary information
                if not self._has_ssid_info():
                    self._prepare()
                else:
                    if self._association_status != \
                        WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED:
                        # Info retrieved in a Probe Response ?
                        # If so, scan in order to get (hopefully) up-to-date
                        # data in another Probe Response
                        if self._previously_associated and \
                            self._ssid_info_learned_in_presp:
                            self._prepare()
                    else:
                        if not self._authentication_status == \
                            WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATING or \
                            not i % 20:
                            if not self._authenticate():
                                self._authentication_status = \
                                    WiFiTrafficHandler.AUTH_STATUS_AUTHENTICATING
                            else:
                                g_default_logger.warning("Could not \
authenticate")

                i = i + 1

            except socket.error as err_mess:
                g_exception_logger.exception(err_mess)
                self._running = False

            except KeyboardInterrupt as keyboard_interrupt:
                # This exception should be caught (ra.py)
                raise keyboard_interrupt


    def stop(self):

        """
        Stop listening, free resources.
        """

        # Send an EAPOL-Logoff frame
        eapol_logoff_frame = EAPOL(version=self._eapol_version, type=2)
        self.send_frame(eapol_logoff_frame)

        if self._association_status != \
            WiFiTrafficHandler.ASSO_STATUS_NOT_ASSOCIATED and \
                self._bssid:
            self._disassociate()
        if self._socket:
            self._socket.close()
        if self._monitor_socket:
            self._monitor_socket.close()

        # Set interface operational state to "DOWN", and linkmode to default
        set_interface_operstate(
            self._iface_index,
            0,
            "UP"
        )
        self._running = False
