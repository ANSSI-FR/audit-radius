*radius-audit* - A RADIUS authentication server audit tool
================

*radius-audit* allows to conduct configuration audits of RADIUS ([RFC 2865](https://tools.ietf.org/html/rfc2865)) servers setup as authentication servers in a [802.1X](http://standards.ieee.org/getieee802/download/802.1X-2004.pdf) environment.

More specifically, *radius-audit* can help auditing the TLS ([RFC 5246](https://tools.ietf.org/html/rfc5246)) configuration of a RADIUS server, as well as discovering authorized EAP ([RFC 3748](https://tools.ietf.org/html/rfc3748)) authentication methods. It can be used by network or system administrators to check the configuration of a RADIUS server, or by pentesters conducting a security audit.

## Installation

This tool is based on [Scapy](https://github.com/secdev/scapy). A recent version of Scapy is recommended. It can be installed as described in the [official  documentation](http://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x).

The `requirements.txt` file contains the list of packages required in order to run *radius-audit*. Apart from Scapy, the current version of the tool only requires [pyroute2](https://github.com/svinota/pyroute2). *pyroute2* is used to setup network interfaces, and to benefit from the [nl80211](https://wireless.wiki.kernel.org/en/developers/documentation/nl80211) drivers of the Linux kernel.

Note that *radius-audit* is compatible with both Python 2 and Python 3.


## Usage

Available arguments are given in the help message (`-h` argument). The different types of scans that *radius-audit* can perform are described in the following sections.


### Wired 802.1X or Wi-Fi

The `iface` argument is mandatory, and is used to provide the network interface that will be used to send and receive the Ethernet frames on a wired network, or to send the 802.11 frames when auditing a wireless network.


### TLS configuration audit

#### TLS scan example

The following example shows how to start a TLS scan.

```
ra -iface eth0 --tls-scan
```

In case of error, an `EAP Failure` response is sent, without any hint regarding the cause of the error. For this reason, in order to make sure that a specific SSL / TLS version is not supported, one has to loop through all the available ciphersuites.

Several other options are available. For example, it is possible to start the scan from a specific TLS version (up to TLS 1.2, starting from SSLv2) using the `-min-tls-version` command line argument. The first SSL / TLS version for which measurements will be performed can be one of the following: `sslv2`, `sslv3`, `tls10`, `tls11`, `tls12`. The following example shows how to launch a scan starting from TLS 1.1:

```
ra -iface eth0 --tls-scan -min-tls-version tls11
```


#### TLS - Specific TLS versions and ciphersuites

The user can provide specific SSL/TLS versions and ciphersuites using the `-tls-versions` and `-tls-ciphers` options:

```
ra -iface eth0 -tls-versions tls10,tls11,tls12 -tls-ciphers 0x0033,0x0035,0x0039,0xc013,0xc014,0x002f,0xc030
Accepted        TLS 1.0         TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.0         TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
Accepted        TLS 1.0         TLS_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.0         TLS_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.0         TLS_DHE_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.0         TLS_DHE_RSA_WITH_AES_256_CBC_SHA
Rejected        TLS 1.0         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Accepted        TLS 1.1         TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.1         TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
Accepted        TLS 1.1         TLS_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.1         TLS_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.1         TLS_DHE_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.1         TLS_DHE_RSA_WITH_AES_256_CBC_SHA
Rejected        TLS 1.1         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Accepted        TLS 1.2         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Accepted        TLS 1.2         TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.2         TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
Accepted        TLS 1.2         TLS_RSA_WITH_AES_256_CBC_SHA
Accepted        TLS 1.2         TLS_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.2         TLS_DHE_RSA_WITH_AES_128_CBC_SHA
Rejected        TLS 1.2         TLS_DHE_RSA_WITH_AES_256_CBC_SHA
```

#### TLS - Test with a specific "TLS-based" EAP authentication method

By default, *radius-audit* will use the EAP-TLS method to perform the scan. However, it is possible to use another "TLS-based EAP" method by adding the `-with-eap-method` command line argument. In the following example, the EAP-TTLS authentication method will be used. 

```
ra -iface eth0 -tls-versions tls12 -tls-ciphers 0x002f -with-eap-method ttls
Accepted        TLS 1.2         TLS_RSA_WITH_AES_128_CBC_SHA
```

*radius-audit* is able to perform scans for the following "TLS-based" EAP methods:


 - [EAP-TLS](https://tools.ietf.org/html/rfc5216)
 - [EAP-TTLS](https://tools.ietf.org/html/rfc5281)
 - [PEAP](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-02)


### Phase 1 authentication - Supported EAP methods enumeration

*radius-audit* allows to enumerate "phase 1" EAP authentication methods that are available. The following example shows how to perform such a scan using the `--discover-phase-1` command line argument:

```
ra -iface eth0 --discover-phase-1
Accepted        4               MD5-Challenge
Rejected        5               One-Time Password (OTP)
Rejected        6               Generic Token Card (GTC)
Rejected        9               RSA Public Key Authentication
Rejected        10              DSS Unilateral
Rejected        11              KEA
Rejected        12              KEA-VALIDATE
Accepted        13              EAP-TLS
Rejected        14              Defender Token (AXENT)
Rejected        15              RSA Security SecurID EAP
Rejected        16              Arcot Systems EAP
Rejected        17              EAP-Cisco Wireless
Rejected        18              GSM Subscriber Identity Modules (EAP-SIM)
Rejected        19              SRP-SHA1
Accepted        21              EAP-TTLS
Rejected        22              Remote Access Service
Rejected        23              EAP-AKA Authentication
Rejected        24              EAP-3Com Wireless
Accepted        25              PEAP
Rejected        26              MS-EAP-Authentication
Rejected        27              Mutual Authentication w/Key Exchange (MAKE)
Rejected        28              CRYPTOCard
Rejected        29              EAP-MSCHAP-V2
Rejected        30              DynamID
Rejected        31              Rob EAP
Rejected        32              Protected One-Time Password
Rejected        33              MS-Authentication-TLV
Rejected        34              SentriNET
Rejected        35              EAP-Actiontec Wireless
Rejected        36              Cogent Systems Biometrics Authentication EAP
Rejected        37              AirFortress EAP
Rejected        38              EAP-HTTP Digest
Rejected        39              SecureSuite EAP
Rejected        40              DeviceConnect EAP
Rejected        41              EAP-SPEKE
Rejected        42              EAP-MOBAC
Accepted        43              EAP-FAST
Rejected        44              ZoneLabs EAP (ZLXEAP)
Rejected        45              EAP-Link
Rejected        46              EAP-PAX
Rejected        47              EAP-PSK
Rejected        48              EAP-SAKE
Rejected        49              EAP-IKEv2
Rejected        50              EAP-AKA
Rejected        51              EAP-GPSK
Rejected        52              EAP-pwd
Rejected        53              EAP-EKE Version 1
Rejected        54              EAP Method Type for PT-EAP
Rejected        55              TEAP
Rejected        255             Experimental
```

This example shows that the targeted RADIUS server seem to support several "TLS-based" EAP authentication methods: [EAP-TLS](https://tools.ietf.org/html/rfc5216), [EAP-TTLS](https://tools.ietf.org/html/rfc5281), [PEAP](https://tools.ietf.org/html/draft-josefsson-pppext-eap-tls-eap-02), and [EAP-FAST](https://tools.ietf.org/html/rfc4851).

At the beginning of the authentication process, when an EAP request for a given authentication method is received, radius-audit assumes that this method is supported by the authentication server. *radius-audit* then tries to restart the authentication process with another method using the *desired authentication type* in a `Legacy Nak` response. This allows to speed up the enumeration process when a given authentication method is supported.


### A few examples

#### Use a wireless interface

*radius-audit* can be used on a Wi-Fi network. In order to do so, the SSID must be given by the user via the`-ssid` command line argument.

```
ra -iface wlan1 -ssid demo-wpa2-eap --tls-scan
```

If an attempt is made to perform a scan on a Wi-Fi network which does not support 802.1X authentication (PSK), a warning message is issued:

```
ra -iface wlan1 -ssid demo-wpa2-psk --discover-phase-1
WARNING: (demo-wpa2-psk) AKM is not IEEE 802.1X / PMKSA caching.
```


#### Specify an identity

The `-identity` command line argument allows to perform the scan with a user-defined identity. When it is not provided, `anonymous` is used as a default value. The `identity` is sent in response to the `EAP Identity` request that begins the EAP authentication process. 

```
ra -iface eth0 -identity johndoe --tls-scan
```

#### Output format

The `--json-output` command line argument can be used to print the results in JSON format:

```
ra -iface eth0 --tls-scan -min-tls-version tls11 --json-output
{"tls_version": "TLS 1.1", "tls_cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "outcome": true, "session_id": true}
{"tls_version": "TLS 1.1", "tls_cipher_suite": "TLS_NULL_WITH_NULL_NULL", "outcome": false}
{"tls_version": "TLS 1.1", "tls_cipher_suite": "TLS_RSA_WITH_NULL_MD5", "outcome": false}
{"tls_version": "TLS 1.1", "tls_cipher_suite": "TLS_RSA_WITH_NULL_SHA", "outcome": false}
[ ... ]
{"tls_version": "TLS 1.1", "tls_cipher_suite": "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", "outcome": false}
{"tls_version": "TLS 1.2", "tls_cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "outcome": true, "session_id": true}
{"tls_version": "TLS 1.2", "tls_cipher_suite": "TLS_NULL_WITH_NULL_NULL", "outcome": false}
{"tls_version": "TLS 1.2", "tls_cipher_suite": "TLS_RSA_WITH_NULL_MD5", "outcome": false}
{"tls_version": "TLS 1.2", "tls_cipher_suite": "TLS_RSA_WITH_NULL_SHA", "outcome": false}
[...]
```

```
ra -iface eth0 --discover-phase-1 --json-output
{"auth_method": 4, "auth_method_desc": "MD5-Challenge", "outcome": true}
{"auth_method": 5, "auth_method_desc": "One-Time Password (OTP)", "outcome": false}
```

### How to speed up the scanning process  ?

An administrator may be able to tune the timers available on the authenticator (switch, Wi-Fi access point) or on the server. For example, the *quietPeriod* timer value on the authenticators may be decreased in order to speed up the process (for more information, one can read the [IEEE Std 802.1X-2004](http://standards.ieee.org/getieee802/download/802.1X-2004.pdf) standard). On Cisco switches, the following command, applied to an interface, allows to decrease the *quietPeriod* to 1 second.

```
sw(config-if)# dot1x timeout quiet-period 1
```

### Acknowledgements

Thanks to Arnaud Ebalard, Nicolas Iooss, Guillaume Valadon and Philippe Valembois for their valuable input.


### License

This project is licensed under the terms of the MIT license.
