# Curfew, An 802.11w-2009 Auditor

This program is designed to see which access points in your local area support management frame protection, and then tries a layer 2 deauthentication flood on them, which is classified as a denial-of-service attack.

This can be seen a  _"wi-fi jammer"_, however its primary goal first is to display and check the first byte of the RSN Capabilities offset, which is found in the RSN Information element.

## Why

The [802.11w-2009 amendment](https://en.wikipedia.org/wiki/IEEE_802.11w-2009) was introduced in 2009. More access points and stations should support it by default. This DoS attack is extremely simplistic to perform by literally anyone with a wireless device that can send out custom layer 2 frames. Wireless cracking and security suites like Aircrack-ng already allow you to do it, and there's probably numerous scripts existing that are centered around roaming. 

There's two flags for protection of management frames: required `01000000` and capable `10000000`. Even access points should at least be _able_ to protect management frames if the device also has the capability, but it's still rare. It's also likely the fact that many devices do support it; hence, it's just not enabled.

Basic deauthentication attacks aren't a real issue, but rather further exploits that can be achieved (or even discovered) due to the management frames not being protected. This is too basic but effective at what it does compared to jamming radio signals the traditional way of noise generation.

Again, consumer routers don't really support this in my experience (or have it disabled for compatibility reasons by default), I expect enterprise hardware to do the opposite.

## Requirements

1. A wireless interface that is capable of RFMON (monitor mode) and injection.
2. A Linux machine with PCAP installed. Windows is obviously not supported.

If your device does not support the first requirement, you effectively cannot use this program. Higher TX power often indicates how well your device will receive packets as well, which is extremely important.

## Installation

```
sudo apt-get install libpcap-dev
sudo make
sudo make install
```
The only main dependency is libpcap. This was created with C89/ANSI C and the compiler used is GCC. Installing is not necessary as you can just use the program from the current directory you're in, but it can also be uninstalled with `sudo make uninstall`.

## Usage

When starting, try doing:

```
sudo curfew -d <interface> -c 2 -m <client MAC address>
```

If you don't specify a MAC address or don't ignore a specific BSSID, it will attempt to deauthenticate everyone (including your devices).

Use `-h` or `--help` to see all the options in much more depth. Using the FIFO scheduling policy seems to be the fastest, but it is negligible.

## Things To Do, Check, And Improve

1. Switch to raw sockets for faster flooding of the deauthentication frames, as right now it's pretty slow with PCAP's approach if no client is specified.
2. Make sure the RSN capabilities part of the parsing is done correctly and does indeed show if an AP requires management frame protection, need an outside confirmation.
3. Not quite sure if the multi-threading is adequate, may just be IO limited?
4. Begin to use GCC optimizations, currently disabled so they don't break anything.

I'm sure there's more than a few bugs and bad code as I am still new to C, all criticism welcome.

## License

This software uses the MIT license and was created by me, Ravjot Singh Samra.

Use regular expression `/\*(.|\n)*?\*/` in your editor/IDE to remove all comments.
