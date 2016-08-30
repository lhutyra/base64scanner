# base64scanner

This utility scans binary file for base64 strings.

Run it for options available.

## Examples

### Oracle RDBMS 11.2 win32

... has some false positives (function names treated as base64, whole base64 alphabet has been treated as base64 string),
but there is something at the end:

```
base64scanner <dennis(a)yurichev.com> (2015-2016; compiled at Aug 30 2016)

*** CRC64=0x7a8e7a41a8bc63bc size=18
base64="xspgenqBIDCommittedGen01"
entropy=3.91
0000000000000000: C6 CA 60 7A 7A 81 20 30-A8 9A 68 AD B5 E7 46 7A "..`zz. 0..h...Fz"
0000000000000010: 7D 35                                           "}5              "
binary file saved to buf_7a8e7a41a8bc63bc.dat
found at:
fname=oracle.exe pos=104072540 (0x634055c)

*** CRC64=0x75f5ed59e47b8e69 size=48
base64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
entropy=5.42
0000000000000000: 00 10 83 10 51 87 20 92-8B 30 D3 8F 41 14 93 51 "....Q. ..0..A..Q"
0000000000000010: 55 97 61 96 9B 71 D7 9F-82 18 A3 92 59 A7 A2 9A "U.a..q......Y..."
0000000000000020: AB B2 DB AF C3 1C B3 D3-5D B7 E3 9E BB F3 DF BF "........]......."
binary file saved to buf_75f5ed59e47b8e69.dat
found at:
fname=oracle.exe pos=102663712 (0x61e8620)
fname=oracle.exe pos=103108896 (0x6255120)

*** CRC64=0x6c44630f2627cea6 size=18
base64="qmxtr2BuildOpn4GetNumStr"
entropy=4.06
0000000000000000: AA 6C 6D AF 60 6E 8A 57-4E A6 7E 06 7A D3 6E 99 ".lm.`n.WN.~.z.n."
0000000000000010: 2B 6B                                           "+k              "
binary file saved to buf_6c44630f2627cea6.dat
found at:
fname=oracle.exe pos=99683016 (0x5f10ac8)
fname=oracle.exe pos=99683044 (0x5f10ae4)
fname=oracle.exe pos=104018652 (0x63332dc)
fname=oracle.exe pos=104072512 (0x6340540)
fname=oracle.exe pos=104072568 (0x6340578)

*** CRC64=0x9936eacc8f52356 size=39
base64="y9YUHJBtpfdwk6D1EItwgQ3UKWLAIMzh8uf3ensK2AHDUWCksaGY"
entropy=5.18
0000000000000000: CB D6 14 1C 90 6D A5 F7-70 93 A0 F5 10 8B 70 81 ".....m..p.....p."
0000000000000010: 0D D4 29 62 C0 20 CC E1-F2 E7 F7 7A 7B 0A D8 01 "..)b. .....z{..."
0000000000000020: C3 51 60 A4 B1 A1 98                            ".Q`....         "
binary file saved to buf_9936eacc8f52356.dat
found at:
fname=oracle.exe pos=102425184 (0x61ae260)
```

### Ubuntu 15.10 i386 installation ISO


```
base64scanner <dennis(a)yurichev.com> (2015-2016; compiled at Aug 30 2016)

*** CRC64=0x7f59fd79eef0476a size=48
base64="iEYEABECAAYFAlYnuuEACgkQRhgUM/u3VFHP5gCgladJt/RVjaWZG5f7V3Jmb9f+"
entropy=5.25
0000000000000000: 88 46 04 00 11 02 00 06-05 02 56 27 BA E1 00 0A ".F........V'...."
0000000000000010: 09 10 46 18 14 33 FB B7-54 51 CF E6 00 A0 95 A7 "..F..3..TQ......"
0000000000000020: 49 B7 F4 55 8D A5 99 1B-97 FB 57 72 66 6F D7 FE "I..U......Wrfo.."
binary file saved to buf_7f59fd79eef0476a.dat
found at:
fname=ubuntu-15.10-desktop-i386.iso pos=2762818 (0x2a2842)
fname=ubuntu-15.10-desktop-i386.iso pos=2762883 (0x2a2883)
fname=ubuntu-15.10-desktop-i386.iso pos=145333108 (0x8a99b74)
fname=ubuntu-15.10-desktop-i386.iso pos=427536955 (0x197bb23b)
fname=ubuntu-15.10-desktop-i386.iso pos=1220753696 (0x48c33920)
```

It turns out, this was someone's PGP signature.

### Max OS X 10.7.4 installation DMG

If *--ascii-only* option set, we see that Apple developes encodes ASCII strings into base64, don't know why and where:

```
$ ./base64scanner --limit-to-ascii Mac\ OS\ X\ Install\ ESD.dmg

base64scanner <dennis(a)yurichev.com> (2015-2016; compiled at Aug 30 2016)

*** CRC64=0x78db6d79718d7909 size=33
base64="L3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3Qt"
entropy=4.19
0000000000000000: 2F 77 77 77 2E 61 70 70-6C 65 2E 63 6F 6D 2F 44 "/www.apple.com/D"
0000000000000010: 54 44 73 2F 50 72 6F 70-65 72 74 79 4C 69 73 74 "TDs/PropertyList"
0000000000000020: 2D                                              "-               "
binary file saved to buf_78db6d79718d7909.dat
found at:
fname=Mac OS X Install ESD.dmg pos=4179716502 (0xf9216996)
fname=Mac OS X Install ESD.dmg pos=4179717185 (0xf9216c41)
fname=Mac OS X Install ESD.dmg pos=4179717868 (0xf9216eec)

*** CRC64=0x337c4b30c00ad87d size=33
base64="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRG"
entropy=4.45
0000000000000000: 3C 3F 78 6D 6C 20 76 65-72 73 69 6F 6E 3D 22 31 "<?xml version="1"
0000000000000010: 2E 30 22 20 65 6E 63 6F-64 69 6E 67 3D 22 55 54 ".0" encoding="UT"
0000000000000020: 46                                              "F               "
binary file saved to buf_337c4b30c00ad87d.dat
found at:
fname=Mac OS X Install ESD.dmg pos=4179716355 (0xf9216903)
fname=Mac OS X Install ESD.dmg pos=4179717038 (0xf9216bae)
fname=Mac OS X Install ESD.dmg pos=4179717721 (0xf9216e59)
```

