## Changelog for Curfew

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
