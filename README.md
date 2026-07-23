# Udp2raw-tunnel


A Tunnel which turns UDP Traffic into Encrypted FakeTCP/UDP/ICMP Traffic by using Raw Socket, helps you Bypass UDP FireWalls(or Unstable UDP Environment).

When used alone,udp2raw tunnels only UDP traffic. Nevertheless,if you used udp2raw + any UDP-based VPN together,you can tunnel any traffic(include TCP/UDP/ICMP),currently OpenVPN/L2TP/ShadowVPN and [tinyfecVPN](https://github.com/wangyu-/tinyfecVPN) are confirmed to be supported.


![image0](images/image0.PNG)

or

![image_vpn](images/udp2rawopenvpn.PNG)

[udp2raw wiki](https://github.com/wangyu-/udp2raw-tunnel/wiki)

[简体中文](/doc/README.zh-cn.md)


# Support Platforms
Linux host (including desktop Linux,Android phone/tablet,OpenWRT router,or Raspberry PI) with root account or cap_net_raw capability.

For Windows and MacOS users, use the udp2raw in [this repo](https://github.com/wangyu-/udp2raw-multiplatform).

# Features
### Send/Receive UDP Packets with ICMP/FakeTCP/UDP headers
ICMP/FakeTCP headers help you bypass UDP blocking, UDP QOS or improper UDP NAT behavior on some ISPs. In ICMP header mode,udp2raw works like an ICMP tunnel.

UDP headers are also supported. In UDP header mode, it behaves just like a normal UDP tunnel, and you can just make use of the other features (such as encryption, anti-replay, or connection stabilization).

### Simulated TCP with Real-time/Out-of-Order Delivery
In FakeTCP header mode,udp2raw simulates 3-way handshake while establishing a connection,simulates seq and ack_seq while data transferring. It also simulates a few TCP options such as: `MSS`, `sackOk`, `TS`, `TS_ack`, `wscale`. Firewalls will regard FakeTCP as a TCP connection, but its essentially UDP: it supports real-time/out-of-order delivery(just as normal UDP does), no congestion control or re-transmission. So there wont be any TCP over TCP problem when using OpenVPN.

### Encryption, Anti-Replay
* Encrypt your traffic with AES-128-CBC.
* Protect data integrity by HMAC-SHA1 (or weaker MD5/CRC32).
* Defense replay attack with anti-replay window.

[Notes on encryption](https://github.com/wangyu-/udp2raw-tunnel/wiki/Notes-on-encryption)

### Failure Dectection & Stabilization (Connection Recovery)
Conection failures are detected by heartbeats. If timed-out, client will automatically change port number and reconnect. If reconnection is successful, the previous connection will be recovered, and all existing UDP conversations will stay vaild.

For example, if you use udp2raw + OpenVPN, OpenVPN won't lose connection after any reconnect, **even if network cable is re-plugged or WiFi access point is changed**.

### Other Features
* **Multiplexing** One client can handle multiple UDP connections, all of which share the same raw connection.

* **Multiple Clients** One server can have multiple clients.

* **NAT Support** All of the 3 modes work in NAT environments.

* **OpenVZ Support** Tested on BandwagonHost VPS.

* **Easy to Build** No dependencies.To cross-compile udp2raw,all you need to do is just to download a toolchain,modify makefile to point at the toolchain,run `make cross` then everything is done.(Note:Pre-compiled binaries for Desktop,RaspberryPi,Android,some Openwrt Routers are already included in [Releases](https://github.com/wangyu-/udp2raw-tunnel/releases))

### Keywords
`Bypass UDP QoS` `Bypass UDP Blocking` `Bypass OpenVPN TCP over TCP problem` `OpenVPN over ICMP` `UDP to ICMP tunnel` `UDP to TCP tunnel` `UDP over ICMP` `UDP over TCP`

# Getting Started
### Installing
Download binary release from https://github.com/wangyu-/udp2raw-tunnel/releases

### Running
Assume your UDP is blocked or being QOS-ed or just poorly supported. Assume your server ip is 44.55.66.77, you have a service listening on udp port 7777.

```bash
# Run at server side:
./udp2raw_amd64 -s -l0.0.0.0:4096 -r 127.0.0.1:7777    -k "passwd" --raw-mode faketcp -a

# Run at client side
./udp2raw_amd64 -c -l0.0.0.0:3333  -r44.55.66.77:4096  -k "passwd" --raw-mode faketcp -a
```
(The above commands need to be run as root. For better security, with some extra steps, you can run udp2raw as non-root. Check [this link](https://github.com/wangyu-/udp2raw-tunnel/wiki/run-udp2raw-as-non-root) for more info  )

###### Server Output:
![](images/output_server.PNG)
###### Client Output:
![](images/output_client.PNG)

Now,an encrypted raw tunnel has been established between client and server through TCP port 4096. Connecting to UDP port 3333 at the client side is equivalent to connecting to port 7777 at the server side. No UDP traffic will be exposed.

### Note
To run on Android, check [Android_Guide](https://github.com/wangyu-/udp2raw/wiki/Android-Guide)

`-a` option automatically adds an iptables rule (or a few iptables rules) for you, udp2raw relies on this iptables rule to work stably. Be aware you dont forget `-a` (its a common mistake). If you dont want udp2raw to add iptables rule automatically, you can add it manually(take a look at `-g` option) and omit `-a`.


# Advanced Topic
### Usage
```
udp2raw-tunnel
git version:4623f878e0    build date:Nov  3 2024 23:15:46
repository: https://github.com/wangyu-/udp2raw-tunnel

usage:
    run as client : ./this_program -c -l local_listen_ip:local_port -r server_address:server_port  [options]
    run as server : ./this_program -s -l server_listen_ip:server_port -r remote_address:remote_port  [options]

common options,these options must be same on both side:
    --raw-mode            <string>        available values:faketcp(default),udp,icmp and easy-faketcp
    -k,--key              <string>        password to gen symetric key,default:"secret key"
    --cipher-mode         <string>        available values:aes128cfb,aes128cbc(default),xor,none
    --auth-mode           <string>        available values:hmac_sha1,md5(default),crc32,simple,none
    -a,--auto-rule                        auto add (and delete) iptables rule
    -g,--gen-rule                         generate iptables rule then exit,so that you can copy and
                                          add it manually.overrides -a
    --disable-anti-replay                 disable anti-replay,not suggested
    --fix-gro                             try to fix huge packet caused by GRO. this option is at an early stage.
                                          make sure client and server are at same version.
client options:
    --source-ip           <ip>            force source-ip for raw socket
    --source-port         <port>          force source-port for raw socket,tcp/udp only
                                          this option disables port changing while re-connecting
other options:
    --conf-file           <string>        read options from a configuration file instead of command line.
                                          check example.conf in repo for format
    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program,
                                          check readme.md in repository for supported commands.
    --log-level           <number>        0:never    1:fatal   2:error   3:warn
                                          4:info (default)     5:debug   6:trace
    --log-position                        enable file name,function name,line number in log
    --disable-color                       disable log color
    --disable-bpf                         disable the kernel space filter,most time its not necessary
                                          unless you suspect there is a bug
    --dev                 <string>        bind raw socket to a device, not necessary but improves performance
    --sock-buf            <number>        buf size for socket,>=10 and <=10240,unit:kbyte,default:1024
    --force-sock-buf                      bypass system limitation while setting sock-buf
    --seq-mode            <number>        seq increase mode for faketcp:
                                          0:static header,do not increase seq and ack_seq
                                          1:increase seq for every packet,simply ack last seq
                                          2:increase seq randomly, about every 3 packets,simply ack last seq
                                          3:simulate an almost real seq/ack procedure(default)
                                          4:similiar to 3,but do not consider TCP Option Window_Scale,
                                          maybe useful when firewall doesnt support TCP Option
    --lower-level         <string>        send packets at OSI level 2, format:'if_name#dest_mac_adress'
                                          ie:'eth0#00:23:45:67:89:b9'.or try '--lower-level auto' to obtain
                                          the parameter automatically,specify it manually if 'auto' failed
    --wait-lock                           wait for xtables lock while invoking iptables, need iptables v1.4.20+
    --gen-add                             generate iptables rule and add it permanently,then exit.overrides -g
    --keep-rule                           monitor iptables and auto re-add if necessary.implys -a
    --hb-len              <number>        length of heart-beat packet, >=0 and <=1500
    --mtu-warn            <number>        mtu warning threshold, unit:byte, default:1375
    --clear                               clear any iptables rules added by this program.overrides everything
    --retry-on-error                      retry on error, allow to start udp2raw before network is initialized
    -h,--help                             print this help message
```

### Iptables rules,`-a` and `-g`
This program sends packets via raw socket. In FakeTCP mode, Linux kernel TCP packet processing has to be blocked by a iptables rule on both sides, otherwise the kernel will automatically send RST for an unrecongized TCP packet and you will sustain from stability / peformance problems. You can use `-a` option to let the program automatically add / delete iptables rule on start / exit. You can also use the `-g` option to generate iptables rule and add it manually.

### `--cipher-mode` and `--auth-mode`
It is suggested to use `aes128cbc` + `hmac_sha1` to obtain maximum security. If you want to run the program on a router, you can try `xor` + `simple`, which can fool packet inspection by firewalls the most of time, but it cannot protect you from serious attacks. Mode none is only for debugging purpose. It is not recommended to set the cipher-mode or auth-mode to none.

### `--seq-mode`
The FakeTCP mode does not behave 100% like a real tcp connection. ISPs may be able to distinguish the simulated tcp traffic from the real TCP traffic (though it's costly). seq-mode can help you change the seq increase behavior slightly. If you experience connection problems, try to change the value.

### `--lower-level`
`--lower-level` allows you to send packet at OSI level 2(link level),so that you can bypass any local iptables rules. If you have a complicated iptables rules which conflicts with udp2raw and you cant(or too lazy to) edit the iptables rules,`--lower-level` can be very useful. Try `--lower-level auto` to auto detect the parameters,you can specify it manually if `auto` fails.

Manual format `if_name#dest_mac_adress`,ie:`eth0#00:23:45:67:89:b9`.

### `--keep-rule`
Monitor iptables and auto re-add iptables rules(for blocking kernel tcp processing) if necessary.Especially useful when iptables rules may be cleared by other programs(for example,if you are using openwrt,everytime you changed and commited a setting,iptables rule may be cleared and re-constructed).

### `--conf-file`

You can also load options from a configuration file in order to keep secrets away from `ps` command.

For example, rewrite the options for the above `server` example (in Getting Started section) into configuration file:

`server.conf`

```
-s
# You can add comments like this
# Comments MUST occupy an entire line
# Or they will not work as expected
# Listen address
-l 0.0.0.0:4096
# Remote address
-r 127.0.0.1:7777
-a
-k passwd
--raw-mode faketcp
```

Pay attention to the `-k` parameter: In command line mode the quotes around the password will be removed by shell. In configuration files we do not remove quotes.

Then start the server with

```bash
./udp2raw_amd64 --conf-file server.conf
```

### `--fifo`
Use a fifo(named pipe) for sending commands to the running program. For example `--fifo fifo.file`.

At client side,you can use `echo reconnect >fifo.file` to force client to reconnect.Currently no command has been implemented for server.

# Peformance Test
#### Test method:
iperf3 TCP via OpenVPN + udp2raw
(iperf3 UDP mode is not used because of a bug mentioned in this issue: https://github.com/esnet/iperf/issues/296 . Instead, we package the TCP traffic into UDP by OpenVPN to test the performance. Read [Application](https://github.com/wangyu-/udp2raw-tunnel#application) for details.

#### iperf3 command:
```
iperf3 -c 10.222.2.1 -P40
iperf3 -c 10.222.2.1 -P40 -R
```
#### Environments
* **Client** Vultr $2.5/monthly plan (single core 2.4GHz cpu, 512MB RAM, Tokyo, Japan)
* **Server** BandwagonHost $3.99/annually plan (single core 2.0GHz cpu, 128MB RAM, Los Angeles, USA)

### Test1
raw_mode: faketcp  cipher_mode: xor  auth_mode: simple

![image4](images/image4.PNG)

(reverse speed was simliar and not uploaded)

### Test2
raw_mode: faketcp  cipher_mode: aes128cbc  auth_mode: md5

![image5](images/image5.PNG)

(reverse speed was simliar and not uploaded)

# Preconnect Branch — Anti Traffic-Policing Features

This fork (`preconnect` branch) adds client-side port/source-address rotation and make-before-break handshaking to defeat ISP/GFW per-flow traffic policing.

## Port Rotation (`--rotate-*`)

When an ISP throttles or resets a single flow after sustained volume, rotating to a fresh outer 5-tuple (new source address + new remote port) before the throttle window avoids the kill. Available on the client side only.

| Option | Default | Description |
|--------|---------|-------------|
| `--rotate-bytes` | 0 (off) | Rotate after N payload bytes, e.g. `10485760` (10 MB) |
| `--rotate-jitter` | 40 | ±percentage on `--rotate-bytes`, creating a spread so rotations are not periodic |
| `--rotate-min-interval` | 20 | Minimum seconds between two rotations (prevents thrashing) |
| `--rotate-max-interval` | 0 (off) | Force a rotation every N seconds regardless of byte count; useful when the ISP kill is time-based |
| `--rotate-ports` | — | Remote port range, e.g. `6100:6131`. The client picks a new port from the range on every rotation |
| `--rotate-stall` | 8 | Also rotate when uplink stays below 64 KB for N seconds while the connection is ready. 0 = disabled. Escapes clamp-to-zero fuses that produce no bytes and never trigger `--rotate-bytes` |

## IPv6 Source Address Rotation (`--rotate-v6-*`)

> Requires a delegated /64 prefix on the client WAN interface.

`--rotate-v6-prefix <addr/64>` and `--rotate-v6-dev <wan-ifname>` instruct the client to `ip -6 addr add` a fresh random /128 address from the prefix on every rotation, *before* opening the new connection. The old address is **deferred** for deletion until the handshake completes and the old socket is closed — both old and new addresses coexist on the interface, so the predictive preconnect socket stays valid across rotations.

`deferred_v6_cleanup()` is called after every swap to delete the old address.

## IPv6 Destination Pool (`--rotate-dst`)

`--rotate-dst <addr1,addr2,...>` — comma-separated IPv6 destination address pool. Every rotation also jumps to a different remote address, so flows differ on all five tuple fields. Requires the server to have all pool addresses assigned to its WAN interface.

## Multi-Listen Server (`-l` + `--l2`)

The server supports range listeners and additional families on the same process:

```bash
# Single process covering v4 :6000-6030 + v6 :6100-6131
udp2raw -s -l 0.0.0.0:6000-6030 --l2 [::]:6100-6131 -r 127.0.0.1:7000 -k <key> --raw-mode udp
```

## Make-Before-Break Preconnect

On the client, every rotation starts a background preconnect to the **next** destination port while the old connection keeps carrying data. When the next rotation fires, the preconnect is already in `client_ready` state — the swap is a zero-downtime socket-fd exchange + memcpy of the completed handshake state. If the preconnect isn't ready yet (first rotation or rapid reconnects), the old connection covers the handshake overlap (~400 ms).

The preconnect is kept alive with periodic heartbeats via the existing `client_on_timer` path.

### Debug Logging

Enable stdout logging to see 5-tuple changes:

```bash
# Client
udp2raw -c ...  > /var/log/udp2raw.log
```

Example log entry:
```
rotation 5-tuple: src=2409:8a00:19dc:d740:c82b:cf3b:7194:300a:62632  dst=2600:3c01:e000:610:6f1c:b05d:55bd:70f6:6129
```

# wiki

Check wiki for more info:

https://github.com/wangyu-/udp2raw-tunnel/wiki
