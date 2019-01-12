## Changelog for Curfew

## 2.01 - 13th January 2019
### Added
- Installation shell script that installs the program and checks dependencies

### Changed / Fixed
- Fixed sequence number mismatches even with sequence numbering disabled
- Makefile tweaks
- GCC pragmas for ignoring false warning in the meantime

### Removed
- Scan flag for "high accuracy", seemed to do nothing, and is undefined on recent versions

## 2.00 - 31st December 2018
### Added
- Completely reworked from the ground up
- Usage of Netlink for more reliable and standard scanning purposes
- Built-in frequency/channel shifter
- Frame burst rate per targeted access point
- Both IOCTL and Netlink methods for setting up wireless interfaces

### Changed / Fixed
- Frames no longer transmit on incorrect channels
- Scheduling is now just handled by the kernel itself
- Usage of raw sockets directly for maximum speed
- All GCC optimisations are now possible without issues
- Standard is now set to C99 for the Netlink libraries, but C89/ANSI is used for Curfew
- Source code is more easier read on a standard terminal (80 column limit)

### Removed
- Curfew is no longer multithreaded via pthreads, as it had little benefit
- User specified process scheduling options are no longer possible
- pcap has been entirely removed from Curfew
- Colour output is currently not developed
- Collection clearing and roaming options are unavailable
- Full RSN capabilities binary dump view

## 1.01 - 11th March 2018
### Added
- Option for deauthenticating specific access point only
- Loop that avoids targeted and ignored BSSIDs clashing
- Much faster and consistent capture thread exit

### Changed / Fixed
- Fixed segmentation fault during capture thread exit on some devices
- Fixed odd "mon0, mon1, etc." device creations on abrupt exits and errors
- More sensible buffer size and snapshot length
- Corrected help text (duplicate -m changed to -i)
- Fixed priority maximums and minimums not being correct for specific scheduling algorithms
- Changed "starting" message information and "too many threads" message, added more detail
- Edited the readme file for clarity and phrasing purposes

### Removed
- Unnecessary timeout for non-activated handle
