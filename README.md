## Knock-cygwin32: A port-knocking implementation on Cygwin32 for Windows

Copyright (c) 2004, Judd Vinet <jvinet@zeroflux.org>

Read the original README_original.md!!

### Building

To build knockd for Cygwin, we need to have Cygwin32-X86 for which we can still install libpcap support.

- Install cygwin32 (not cygwinx64!) https://www.cygwin.com/setup-x86.exe

  `c:\tmp> wget https://www.cygwin.com/setup-x86.exe`

  `c:\tmp> setup-x86.exe -q -P autoconf,autoconf2.5,autogen,automake,automake1.15,libtool,make,gcc-g++,mingw64-x86_64-gcc-core,mingw64-x86_64-gcc-g++,python37,python37-devel,python3-configobj,libopenmpi-devel,openmpi,vim,rsh,wget,zlib-devel,git`
- Install WinPcap for Windows 
  https://www.winpcap.org/install/default.htm e.g. https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe

  `c:\tmp> wget https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe`
  
  `c:\tmp> .\WinPcap_4_1_3.exe`
  
  Verify in CygwinX86 that NOW works
  
  `$ which packet.dll wpcap.dll`
  
  `/cygdrive/c/Windows/system32/packet.dll`
  
  `/cygdrive/c/Windows/system32/wpcap.dll`
  
  `$`


  
- Install WinPcap Devel for Windows (to copy the necessary files to cygwin x86 DEV environment)
  https://www.winpcap.org/devel.htm e.g. https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip
  
  `c:\tmp> wget https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip`
  
  Download and unzip the pack. 

  Copy libraries like this:

  `c:\tmp>copy WpdPack_4_1_2\WpdPack\Lib\libpacket.a c:\cygwin\lib\`

  `c:\tmp>copy WpdPack_4_1_2\WpdPack\Lib\libwpcap.a c:\cygwin\lib\`


  Create a folder cygwin\usr\include\pcap\

  `c:\tmp>mkdir c:\cygwin\usr\include\pcap\`

Copy all headers from WpdPack\Include to cygwin\usr\include\pcap\

`c:\tmp>copy WpdPack_4_1_2\Include\*.* c:\cygwin\usr\include\pcap\`

`c:\tmp>mkdir c:\cygwin\usr\include\pcap\pcap`

`c:\tmp>copy WpdPack_4_1_2\Include\pcap\*.* c:\cygwin\usr\include\pcap\pcap`

- Place missing ether header files in cygwin environment

`  $ wget https://svnweb.freebsd.org/base/head/sys/net/ethernet.h -O /usr/include/net/ethernet.h`

`  $ wget https://svnweb.freebsd.org/base/head/sys/net/if_arp.h -O /usr/include/net/if_arp.h`
 
`  $ wget https://svnweb.freebsd.org/base/head/sys/netinet/if_ether.h -O /usr/include/netinet/if_ether.h`

`  $ echo (Could not find netinet/if_arp.h but luckily it is not needed)`


- Compile inside cygwin32

`  $ git clone https://github.com/triple-it/knock-cygwin32.git`

`  $ cd knock-cygwin32`

`  $ autoreconf -fi`

`  $ ./configure --prefix=/usr/local`

`  $ make`

`  $ sudo make install`

```
## Minor Interface length change
To support the Windows long interface names, I made a small patch...

$ git diff src/knockd.c
diff --git a/src/knockd.c b/src/knockd.c
index eff10bc..207caff 100644
--- a/src/knockd.c
+++ b/src/knockd.c
@@ -55,6 +55,7 @@
 #include <getopt.h>
 #include <syslog.h>
 #include <pcap.h>
 #include <errno.h>
 #include "list.h"

@@ -162,7 +163,8 @@ int  o_debug     = 0;
 int  o_daemon    = 0;
 int  o_lookup    = 0;
 int  o_skipIpV6  = 0;
-char o_int[32]           = "";         /* default (eth0) is set after parseconf
ig() */
+//char o_int[32]           = "";               /* default (eth0) is set after p
arseconfig() */
+char o_int[64]           = "";         /* Otherwise we cannot put in long inter
face names like "-i "\Device\NPF_{32CF62AB-06A1-4A29-BF50-3BB2366AFC79}" */
 char o_cfg[PATH_MAX]     = "/etc/knockd.conf";
 char o_pidfile[PATH_MAX] = "/var/run/knockd.pid";
 char o_logfile[PATH_MAX] = "";

~/knock$
```

## Make a test run

Copy cygwin1.dll to make it possible to run knockd outside of Cygwin environment, which could be conveniant.

`c:\tmp> copy \cygwin\bin\cygwin1.dll \cygwin\home\user\knock\.`

```
C:\cygwin\home\user\knock> more knockd.conf
#[options]
#       logfile = /var/log/knockd.log

[openSSH]
        sequence    = 7000,8000,9000
        seq_timeout = 5
#       command     = /usr/sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        command     = netsh advfirewall firewall add rule name="knock" dir=in protocol=tcp localport=3389 remoteip="1.1.1.1" action=allow
        tcpflags    = syn

[closeSSH]
        sequence    = 9000,8000,7000
        seq_timeout = 5
#       command     = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        command     = netsh advfirewall firewall delete rule name="knock" dir=in protocol=tcp localport=3389 remoteip="1.1.1.1" action=allow
        tcpflags    = syn

[openHTTPS]
        sequence    = 12345,54321,24680,13579
        seq_timeout = 5
        command     = /usr/local/sbin/knock_add -i -c INPUT -p tcp -d 443 -f %IP%
        tcpflags    = syn


C:\cygwin\home\user\knock>


C:\cygwin\home\user\knock>where nmap
C:\Program Files (x86)\Nmap\nmap.exe

C:\cygwin\home\user\knock> echo "find the Windows interface namings via nmap"
C:\cygwin\home\user\knock>  nmap -iflist
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-30 17:35 W. Europe Daylight Time
************************INTERFACES************************
DEV  (SHORT) IP/MASK                                     TYPE     UP   MTU  MAC
eth0 (eth0)  fe80::d09e:9d61:8ce8:5052/64                ethernet down 1500 5E:AC:29:E1:4D:1A
eth0 (eth0)  169.254.80.82/16                            ethernet down 1500 5E:AC:29:E1:4D:1A
eth1 (eth1)  fe80::1486:a6ab:7857:34a3/64                ethernet up   1500 00:15:5D:E0:BA:25
eth1 (eth1)  172.22.240.1/20                             ethernet up   1500 00:15:5D:E0:BA:25
eth2 (eth2)  fe80::900b:3e1b:7d3d:cea1/64                ethernet down 1500 9E:B6:D0:3E:BA:60
eth2 (eth2)  169.254.206.161/16                          ethernet down 1500 9E:B6:D0:3E:BA:60
eth3 (eth3)  fe80::c9ec:6fbf:a554:51fe/64                ethernet down 1500 AE:B6:D0:3E:BA:60
eth3 (eth3)  169.254.81.254/16                           ethernet down 1500 AE:B6:D0:3E:BA:60
eth4 (eth4)  192.168.1.11/24                             ethernet up   1500 00:E0:4C:36:07:44
eth5 (eth5)  fe80::ac11:c56d:9dc6:fe5a/64                ethernet up   1500 00:FF:DB:41:71:3B
eth5 (eth5)  10.18.22.2/24                               ethernet up   1500 00:FF:DB:41:71:3B
eth6 (eth6)  2001:1c04:2f03:7800:1c87:2ceb:d851:13b9/64  ethernet down 1500 9C:B6:D0:3E:BA:60
eth6 (eth6)  2001:1c04:2f03:7800:68e2:f81b:efb9:e0f4/128 ethernet down 1500 9C:B6:D0:3E:BA:60
eth6 (eth6)  fe80::1c87:2ceb:d851:13b9/64                ethernet down 1500 9C:B6:D0:3E:BA:60
eth6 (eth6)  169.254.19.185/16                           ethernet down 1500 9C:B6:D0:3E:BA:60
eth7 (eth7)  fe80::ac87:84ea:5542:fa3e/64                ethernet down 1500 28:C2:1F:66:07:09
eth7 (eth7)  169.254.250.62/16                           ethernet down 1500 28:C2:1F:66:07:09
lo0  (lo0)   ::1/128                                     loopback up   -1
lo0  (lo0)   127.0.0.1/8                                 loopback up   -1

DEV    WINDEVICE
eth0   \Device\NPF_{D612BF4F-8795-4046-AA1D-FE1A3AB432B5}
eth0   \Device\NPF_{D612BF4F-8795-4046-AA1D-FE1A3AB432B5}
eth1   \Device\NPF_{D31123E6-C4DA-4863-8CBB-7A57EBC1ADA0}
eth1   \Device\NPF_{D31123E6-C4DA-4863-8CBB-7A57EBC1ADA0}
eth2   \Device\NPF_{1C7C4BF2-22B2-4D0F-BBB0-C4DBFDFEC028}
eth2   \Device\NPF_{1C7C4BF2-22B2-4D0F-BBB0-C4DBFDFEC028}
eth3   \Device\NPF_{50FC3BB0-D835-4DF0-B23D-15F0E750D3D5}
eth3   \Device\NPF_{50FC3BB0-D835-4DF0-B23D-15F0E750D3D5}
eth4   \Device\NPF_{32CF62AB-06A1-4A29-BF50-3BB2366AFC79}
eth5   \Device\NPF_{DB41713B-959B-46D0-8D8A-53339A0BC18E}
eth5   \Device\NPF_{DB41713B-959B-46D0-8D8A-53339A0BC18E}
eth6   \Device\NPF_{18483F55-F53B-43BA-80F7-B79014530C71}
eth6   \Device\NPF_{18483F55-F53B-43BA-80F7-B79014530C71}
eth6   \Device\NPF_{18483F55-F53B-43BA-80F7-B79014530C71}
eth6   \Device\NPF_{18483F55-F53B-43BA-80F7-B79014530C71}
eth7   \Device\NPF_{5C312B85-9CFE-4D79-ADC7-F53DA69416E3}
eth7   \Device\NPF_{5C312B85-9CFE-4D79-ADC7-F53DA69416E3}
lo0    \Device\NPF_Loopback
lo0    \Device\NPF_Loopback
<none> \Device\NPF_{B98D797D-2010-4EFB-8DD7-1F8189DA6A4E}
<none> \Device\NPF_{B8D02087-4FFC-455C-9DD4-583E1CA42A27}
<none> \Device\NPF_{4B265458-2100-434C-B03D-74DB0967C3F3}

**************************ROUTES**************************
DST/MASK                                    DEV  METRIC GATEWAY
255.255.255.255/32                          eth0 257
.....<redacted> routes

C:\cygwin\home\user\knock>



C:\cygwin\home\user\knock>.\knockd.exe -D -v -c .\knockd.conf -i "\\Device\\NPF_{32CF62AB-06A1-4A29-BF50-3BB2366AFC79}"
config: new section: 'openSSH'
config: openSSH: sequence: 7000:tcp,8000:tcp,9000:tcp
config: openSSH: seq_timeout: 5
config: openSSH: start_command: netsh advfirewall firewall add rule name="knock" dir=in protocol=tcp localport=3389 remoteip="1.1.1.1" action=allow
config: tcp flag: SYN
config: new section: 'closeSSH'
config: closeSSH: sequence: 9000:tcp,8000:tcp,7000:tcp
config: closeSSH: seq_timeout: 5
config: closeSSH: start_command: netsh advfirewall firewall delete rule name="knock" dir=in protocol=tcp localport=3389 remoteip="1.1.1.1" action=allow
config: tcp flag: SYN
config: new section: 'openHTTPS'
config: openHTTPS: sequence: 12345:tcp,54321:tcp,24680:tcp,13579:tcp
config: openHTTPS: seq_timeout: 5
config: openHTTPS: start_command: /usr/local/sbin/knock_add -i -c INPUT -p tcp -d 443 -f %IP%
config: tcp flag: SYN
ethernet interface detected
listening on \\Device\\NPF_{32CF62AB-06A1-4A29-BF50-3BB2366AFC79}...
2022-04-30 17:19:06: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 285 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 60 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: udp: 192.168.1.11:50487 -> 8.8.8.8:53 76 bytes
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 189 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 60 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: udp: 8.8.8.8:53 -> 192.168.1.11:50487 137 bytes
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 173 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 60 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 237 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 269 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: udp: 192.168.1.122:43415 -> 192.168.1.255:10000 69 bytes
2022-04-30 17:19:07: udp: 192.168.1.122:43415 -> 192.168.1.255:10001 69 bytes
2022-04-30 17:19:07: udp: 192.168.1.122:43415 -> 255.255.255.255:10000 69 bytes
2022-04-30 17:19:07: udp: 192.168.1.122:43415 -> 255.255.255.255:10001 69 bytes
2022-04-30 17:19:07: udp: 192.168.1.149:10000 -> 255.255.255.255:10000 171 bytes
2022-04-30 17:19:07: udp: 192.168.1.149:10000 -> 255.255.255.255:10000 171 bytes
2022-04-30 17:19:07: udp: 192.168.1.149:10001 -> 255.255.255.255:10001 171 bytes
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 173 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: udp: 192.168.1.149:10001 -> 255.255.255.255:10001 171 bytes
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 157 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 60 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 685 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 60 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 1434 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 105 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 1434 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 1.2.3.4:443 -> 192.168.1.11:1690 105 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 54 bytes
packet is not SYN, ignoring...
packet is not SYN, ignoring...
packet is not SYN, ignoring...
2022-04-30 17:19:07: tcp: 192.168.1.11:1690 -> 1.2.3.4:443 157 bytes
waiting for child processes...
closing...

C:\cygwin\home\user\knock>
```






