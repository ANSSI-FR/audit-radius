# -*- coding: utf-8 -*-
"""
Contains helper functions.
"""

from pyroute2 import IW, IPRoute, RawIPRoute, IPDB
from pyroute2.netlink.exceptions import NetlinkError

from src.utils.log import g_exception_logger


SIOCGIFFLAGS = 0x8913
SIOCGIFHWADDR = 0x8927
IFF_UP = 0x1
MONITOR_INTERFACE_NAME = "ra0"
PAE_GROUP_ADDR = "01:80:c2:00:00:03"
IEEE_802_1X_ETHERTYPE = 0x888E
ETH_P_ALL = 0x0003


def get_wireless_interface_mac_addr(interface_index):

    """
    Return the MAC address of a wireless interface.
    """

    mac_address = None

    try:
        with IW() as iw:
            data = iw.get_interface_by_ifindex(interface_index)
            if data:
                mac_address = data[0].get_attr("NL80211_ATTR_MAC")
    except NetlinkError as netlink_err:
        g_exception_logger.exception(netlink_err)

    return mac_address


def get_interface_index(iface_name):

    """
    Return the interface index.
    """

    interface_index = None

    try:
        with IPRoute() as ip:
            data = ip.link_lookup(ifname=iface_name)
            if data:
                interface_index = data[0]
    except NetlinkError as netlink_err:
        g_exception_logger.exception(netlink_err)

    return interface_index


def is_wireless_interface(interface_index):

    """
    Return True if the interface which index is interface_index is a wireless
    interface, False otherwise.
    """

    is_valid = True

    try:
        with IW() as iw:
            iw.get_interface_by_ifindex(interface_index)
    except NetlinkError:
        is_valid = False

    return is_valid


def set_interface_admin_state(iface_name, admin_up=True):

    """
    Set interface "iface_name" administrative state.
    """

    done = True

    try:
        with IPDB() as ipdb:
            with ipdb.interfaces[iface_name] as interface:
                if admin_up:
                    interface["flags"] |= IFF_UP
                else:
                    interface["flags"] =~ IFF_UP
    except KeyError as key_err:
        g_exception_logger.exception(key_err)
        done = False
    except Exception as exception:
        g_exception_logger.exception(exception)
        done = False

    return done


def network_interface_status(interface_name):

    """
    Returns True if the network interface "interface_name" is up, False
    otherwise.
    """

    interface_up = False

    try:
        with IPDB() as ipdb:
            with ipdb.interfaces[interface_name] as interface:
                interface_up = interface["operstate"]

    except KeyError as key_err:
        g_exception_logger.exception(key_err)
    except Exception as exception:
        g_exception_logger.exception(exception)

    return interface_up


def get_mac_addr(interface_name):

    """
    Returns the MAC address of a given network interface.
    """

    mac_addr = None

    try:
        with IPDB() as ipdb:
            with ipdb.interfaces[interface_name] as interface:
                mac_addr = interface["address"]

    except KeyError as key_err:
        g_exception_logger.exception(key_err)
    except Exception as exception:
        g_exception_logger.exception(exception)

    return mac_addr


def is_integer(val):

    """
    Helper function that returns True if the provided value is an integer.
    """

    try:
        int(val)
    except ValueError:
        return False
    return True


def is_hex_value(val):

    """
    Helper function that returns True if the provided value is an integer in
    hexadecimal format.
    """

    try:
        int(val, 16)
    except ValueError:
        return False
    return True


def get_interface_operstate(iface_name):

    """
    Set interface operational state.
    https://www.kernel.org/doc/Documentation/networking/operstates.txt
    """

    operstate = None

    try:
        with IPDB() as ipdb:
            if iface_name in ipdb.interfaces.keys():
                with ipdb.interfaces[iface_name] as interface:
                    operstate = interface["operstate"]
    except KeyError as key_err:
        g_exception_logger.exception(key_err)
    except Exception as exception:
        g_exception_logger.exception(exception)

    return operstate


def set_interface_operstate(iface_index, linkmode, operstate):

    """
    Set interface operational state.
    https://www.kernel.org/doc/Documentation/networking/operstates.txt
    """

    done = True

    try:
        with RawIPRoute() as rawip:
            rawip.link(
                'set',
                index=iface_index,
                IFLA_LINKMODE=linkmode,
                IFLA_OPERSTATE=operstate
            )
    except NetlinkError as netlink_err:
        g_exception_logger.exception(netlink_err)
        done = False

    return done


def setup_wireless_interfaces(wireless_iface_name):

    """
    Create a monitor interface ("ra0"), if it does not exist already.
    Bring the wireless interface up if necessary.
    """

    setup_complete = True

    # Get interface index
    iface_index = get_interface_index(wireless_iface_name)

    # Check if it is a provided interface
    if not is_wireless_interface(iface_index):
        setup_complete = False
        g_exception_logger.error("%s is not a wireless interface.",\
wireless_iface_name)
    else:
        if not get_interface_index(MONITOR_INTERFACE_NAME):
            # Create a monitor interface
            try:
                with IW() as iw:
                    iw.add_interface(MONITOR_INTERFACE_NAME, 6, iface_index)
            except NetlinkError as netlink_err:
                g_exception_logger.exception(netlink_err)
                return False

        # Set the monitor interface "administratively" up
        if not set_interface_admin_state(MONITOR_INTERFACE_NAME, admin_up=True):
            g_exception_logger.error("Could not set %s administratively up",\
MONITOR_INTERFACE_NAME)
            setup_complete = False

        # Set the interface "administratively" up
        if not set_interface_admin_state(wireless_iface_name, admin_up=True):
            g_exception_logger.error("Could not set %s administratively up",\
wireless_iface_name)
            setup_complete = False

    return setup_complete


def remove_monitor_interface(monitor_iface_name):

    """
    Remove the virtual monitor interface that should have been added at
    startup.
    """

    index = get_interface_index(monitor_iface_name)
    if index:
        try:
            with IW() as iw:
                iw.del_interface(index)
        except NetlinkError as netlink_err:
            g_exception_logger.exception(netlink_err)
