# Curfew, an 802.11w-2009 Auditor

This program is designed to see which access points in your local area support management frame protection, and then tries a layer 2 deauthentication flood on them, which is classified as a denial-of-service attack.

It can be seen a  _"Wi-Fi jammer"_; however, its primary goal first is to display and check the first byte of the RSN Capabilities offset, which is found in the RSN Information Element, to confirm if an access point is vulnerable or not. 

The difference between Curfew and many other programs made for deauthentication attacks is that Curfew checks pre-hand if an access point is capable of protection or not for auditing purposes, and then tries to send as many deauthentication frames as theoretically possible, hence why Curfew is created entirely in C and not in e.g. Python with Scapy. It also tries to deauthenticate every access point instead of focusing on a single one.

## Why

The [IEEE 802.11w-2009 amendment](https://en.wikipedia.org/wiki/IEEE_802.11w-2009) was introduced in 2009. It is not supported by a fair number of routers and access points in general, and/or it is not utilized. Deauthentication attacks are extremely simplistic to perform by any perpetrator with an 802.11 capable device that can send out custom crafted layer 2 management frames. Wireless cracking and security suites like Aircrack-ng (via `aireplay-ng`) already allow you to perform a deauthentication attack, and there are numerous small existing scripts that are centered around roaming deauthentication for causing disruption. 

There's two flags for notifying protection of management frames: required `01000000` and capable `10000000`. Home routers in particular are very often not capable of management frame protection; thus, it is not required for a connection either. There are also reports of it potentially causing issues when enabled.

Deauthentication attacks aren't a worrying issue, but they can still be utilized in order to perform social engineering attacks on users by getting them to switch to a fake "evil" access point that (from the surface) looks like the access point that they have trouble connecting to. Another use-case of a deauthentication attack is to capture a four-way handshake, which is only possible when a station is authenticating to an access point, hence the station needing to be deauthenticated first.

This DoS attack is a simple but an effective form of jamming as opposed to more classic electronic warfare forms of jamming e.g. spot and sweep, along with being more legally obscure, and it has other uses as well that lead to more than a DoS.

## Requirements

##### An 802.11 wireless device capable of the following:
1. RFMON (monitor mode).
2. IEEE802_11_RADIO (RadioTap header) link-type.
3. Packet/Frame injection.
4. cfg80211/mac80211 driver API support (not just WEXT).

##### An x86-64 system running a GNU/Linux distribution which supports Netlink and nl80211.

##### `libnl-3.0` and `libnl-genl-3.0`, as well as any developer libraries for them if your distribution seperates them as well.

It's also beneficial to have a wireless device that has a high bandwidth rate, as well as having a high TX power value for stronger frame flooding.

## Installation

```
sudo sh INSTALL.sh
```
If the (Generic) Netlink dependency is satisfied, then everything should compile properly.

## Usage

When starting, put your interface up via `ip link` or `ipconfig`, and try doing:

```
sudo curfew -d <interface> -s 5 -b 64 -c <client MAC address>
```

If you don't specify a MAC address or don't ignore a specific BSSID, it will obviously attempt to deauthenticate everyone (including any of your stations and clients). Specifiying `-N` for pure Netlink usage is currently not recommended, as all devices don't have perfectly wonderful driver implementation, so it can cause wild issues or even fatal kernel panics.

Use `-h` or `--help` to see all the options. If you are only going to be attacking a single access point, then setting an extremely high burst rate is recommended for more performance. Using `-b -1` should set the `unsigned int` that stores the burst rate value to `UINT_MAX` due to an overflow.

## Things To Do, Check, And Improve

1. Switch to `PACKET_TX_RING` or even `PF_RING` for more theoretical performance.
2. Reimplement options for roaming and collection clearing, even multithreading for verbosity processing during the attack segment.
3. Rewrite the depreciated IOCTL methods of device configuration to not use `ifconfig` and `iwconfig` via `system()`.
4. Speed up the attack loop by removing exclusion checking from it, and place it somewhere more efficient.
5. Implement a more dynamic and sensible memory allocation routine.

The real purpose of this software is for an excuse to practice maintaining and revising a project, improve my C skills, and increase low-level knowledge of networking and programming, so there's likely to be many bugs hidden or just odd design decisions in general.

## License

This software uses the MIT license and was created by Ravjot Singh Samra. 

Feel absolutely free to use code from here as a starting point for Netlink and nl80211 C programming, since IOCTL is slowly being depreciated and Netlink programming is pretty confusing compared to IOCTL.
