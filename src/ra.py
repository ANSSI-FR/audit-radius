# -*- coding: utf-8 -*-

"""
radius-audit

radius-audit is a tool that can help audit the configuration of RADIUS authentication servers.
"""

from __future__ import print_function

import sys
import argparse

from src import PROG_NAME, VERSION
from src.core.scanner import Scanner
from src.core.eap import TLS_BASED_METHODS_BY_NAME
from src.utils.utils import MONITOR_INTERFACE_NAME, get_interface_index,\
get_mac_addr, get_wireless_interface_mac_addr, is_wireless_interface,\
network_interface_status, set_interface_operstate, setup_wireless_interfaces,\
remove_monitor_interface, is_integer, is_hex_value
from src.utils.tls_helper import get_tls_version_value_from_name,\
cipher_suite_is_valid
from src.utils.log import g_default_logger, g_traffic_logger,\
g_exception_logger


__all__ = []
__version__ = VERSION
__date__ = "2018-09"
__updated__ = "2018-09"
__prog__ = PROG_NAME


def main(argv):

    """
    Handles command line options.
    """

    program_name = __prog__
    program_version = "v{}".format(__version__)
    program_build_date = str(__updated__)
    program_version_message = "{} {} ({})".format(
        program_name,
        program_version,
        program_build_date
    )
    program_shortdesc = "radius-audit - A tool to audit RADIUS authentication servers."
    program_license = """{}

USAGE

Attempt to discover the phase 1 EAP authentication methods:
ra -iface eth0 -identity anonymous --discover-phase-1

Test if the server supports TLS_RSA_WITH_AES_128_CBC_SHA using TLS 1.1:
ra -iface eth0 -identity anonymous -tls-versions tls11 -tls-ciphers 0x002f

Attempt to perform a complete SSL/TLS scan:
ra -iface eth0 -identity anonymous --tls-scan
""".format(program_shortdesc)

    scanner = None
    try:
        parser = argparse.ArgumentParser(
            prog=__prog__,
            description=program_license,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "-v",
            "--verbose",
            dest="verbose",
            action="count",
            help="set verbosity level [default: %(default)s]"
        )
        parser.add_argument(
            "-V",
            "--version",
            action="version",
            version=program_version_message
        )
        parser.add_argument(
            "-iface",
            action="store",
            dest="interface",
            type=str,
            required=True,
            help="provide the network interface to use. Example: eth0"
        )
        parser.add_argument(
            "-ssid",
            action="store",
            dest="ssid",
            type=str,
            required=False,
            help="provide the SSID. Example: test-ssid"
        )
        parser.add_argument(
            "-identity",
            action="store",
            dest="identity",
            type=str,
            default="anonymous",
            required=False,
            help="provide the identity of the peer. Example: anonymous"
        )
        parser.add_argument(
            "--discover-phase-1",
            action="store_true",
            required=False,
            help="attempt to discover authorized phase 1 EAP authentication \
methods."
        )
        parser.add_argument(
            "-phase-1-methods",
            action="store",
            type=str,
            required=False,
            help="test if the given EAP authentication methods are supported. \
Example: 13,21,25 (list of EAP types)"
        )
        parser.add_argument(
            "-with-eap-method",
            action="store",
            type=str,
            required=False,
            help="specify an EAP authentication method based on TLS: \
\"tls\", \"ttls\", or \"peap\"."
        )
        parser.add_argument(
            "-tls-versions",
            action="store",
            type=str,
            required=False,
            help="provide a list of specific SSL/TLS versions (sslv2, sslv3, \
tls10, tls11, tls12)."
        )
        parser.add_argument(
            "-tls-ciphers",
            action="store",
            type=str,
            required=False,
            help="provide a list of SSL/TLS ciphersuites (hex format). \
Example: 0x002e,0x002f"
        )
        parser.add_argument(
            "--tls-scan",
            action="store_true",
            required=False,
            help="attempt to discover available SSL/TLS versions, as well as \
supported ciphersuites. By default, attempts will be made using EAP-TLS. To \
specify another EAP method based on TLS, use the -with-eap-method parameter."
        )
        parser.add_argument(
            "-min-tls-version",
            action="store",
            type=str,
            required=False,
            help="start the scan from the given SSL/TLS version (sslv2, sslv3,\
 tls10, tls11, tls12)."
        )
        parser.add_argument(
            "--json-output",
            action="store_true",
            required=False,
            help="print the results in JSON format."
        )

        if len(argv) < 2:
            parser.print_help()
            return -1

        args = parser.parse_args()
        verbose = args.verbose or 0
        g_default_logger.setLevel(max(3 - verbose, 0) * 10)
        g_traffic_logger.setLevel(max(3 - verbose, 0) * 10)

        # Check if provided network interface exists
        interface_index = get_interface_index(args.interface)
        if not interface_index:
            g_default_logger.error("Could not find interface %s",\
args.interface)
            return -1

        mac_addr = None
        ssid = None
        if args.ssid:
            if not is_wireless_interface(interface_index):
                g_default_logger.error("Provided network interface \
(%s) is not a wireless interface.", args.interface)
                return -1

            ssid = args.ssid
            mac_addr = get_wireless_interface_mac_addr(interface_index)
            if not mac_addr:
                g_default_logger.error("Provided network interface \
(%s) doe    s not exist.", args.interface)
                return -1

            if not setup_wireless_interfaces(args.interface):
                g_default_logger.error("Could not setup the interfaces.")
                return -1

        else:
            if is_wireless_interface(interface_index):
                g_default_logger.error("Provided network interface \
(%s) is not a wired interface.", args.interface)
                return -1

            # Check if provided network interface is up
            if not network_interface_status(args.interface):
                g_default_logger.error("Provided network interface (%s) is \
down.", args.interface)
                return -1

            mac_addr = get_mac_addr(args.interface)
            if not mac_addr:
                g_default_logger.error("Provided network interface \
(%s) does not exist.", args.interface)
                return -1

        # Set the interface operational state to "DORMANT"
        if not set_interface_operstate(interface_index, 1, "DORMANT"):
            g_default_logger.warn("Could not set %s operational state to \
DORMANT.", args.interface)


        discover_phase_1 = False
        phase_1_methods = None
        with_eap_method = None
        tls_scan = False
        tls_versions = None
        tls_ciphers = None
        tls_min_version = None
        json_output = None
        if args.discover_phase_1:
            discover_phase_1 = True
        if args.phase_1_methods:
            phase_1_methods = []
            tmp = args.phase_1_methods.split(',')
            for val in tmp:
                if is_integer(val):
                    phase_1_methods.append(int(val))
        if args.with_eap_method:
            tmp = args.with_eap_method.strip().split(',')
            if not tmp[0] in TLS_BASED_METHODS_BY_NAME:
                print("{} is not a valid / supported \"TLS-based\" EAP \
authentication method. Please choose one of the following: \
\"tls\", \"ttls\", or \"peap\".".format(tmp[0]), file=sys.stderr)
                return -1
            with_eap_method = TLS_BASED_METHODS_BY_NAME[tmp[0]]
        if args.tls_versions:
            tls_versions = []
            tmp = args.tls_versions.split(',')
            for val in tmp:
                tls_version = get_tls_version_value_from_name(val)
                if not tls_version:
                    print("{} is not a valid / supported SSL/TLS version. \
Please choose one of the following: sslv2, sslv3, tls10, tls11, tls12.".\
format(val), file=sys.stderr)
                    return -1
                else:
                    tls_versions.append(tls_version)
        tls_ciphers = []
        if args.tls_ciphers:
            tmp = args.tls_ciphers.split(',')
            for val in tmp:
                if is_hex_value(val):
                    cs_val = int(val, 16)
                    if not cipher_suite_is_valid(cs_val):
                        print("{} is not a valid / supported cipher suite.".\
format(val), file=sys.stderr)
                        return -1
                    else:
                        tls_ciphers.append(cs_val)
        if args.tls_scan:
            tls_scan = True
        if args.min_tls_version:
            tls_version = get_tls_version_value_from_name(args.min_tls_version)
            if not tls_version:
                print("{} is not a valid / supported SSL/TLS version.\n\
Please choose one of the following: sslv2, sslv3, tls10, tls11, tls12.".\
format(tls_version), file=sys.stderr)
                return -1
            # Keep the "name" of the version instead of its actual value
            tls_min_version = args.min_tls_version
        if args.json_output:
            json_output = True

        if discover_phase_1:
            with_eap_method = None
            tls_scan = False
            tls_versions = None
            tls_ciphers = None
            tls_min_version = None

        elif phase_1_methods:
            with_eap_method = None
            tls_scan = False
            tls_versions = None
            tls_ciphers = None
            tls_min_version = None

        else:
            # By default, the tool will attempt to setup TLS sessions using
            # EAP-TLS.
            tls_scan = True

        # Create and start the "scanner"
        scanner = Scanner(
            args.interface,
            mac_addr,
            args.identity,
            ssid,
            phase_1_methods,
            with_eap_method,
            tls_versions,
            tls_ciphers,
            tls_scan,
            tls_min_version,
            json_output
        )
        scanner.start()

    except KeyboardInterrupt as keyboard_exception:
        g_exception_logger.exception(keyboard_exception)
        if scanner:
            scanner.stop()
        if is_wireless_interface(interface_index):
            remove_monitor_interface(MONITOR_INTERFACE_NAME)
        return -1

    except Exception as exception:
        g_exception_logger.exception(exception)
        if scanner:
            scanner.stop()
        if is_wireless_interface(interface_index):
            remove_monitor_interface(MONITOR_INTERFACE_NAME)
        return -1

    if is_wireless_interface(interface_index):
        remove_monitor_interface(MONITOR_INTERFACE_NAME)

    return 0
