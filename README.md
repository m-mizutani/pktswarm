# tcpswarm

`tcpswarm` is a tool to analyze massive TCP/IP traffic instantly. There are useful tools to analyze TCP/IP traffic, e.g. wireshark, tcpdump, tcpstat, etc. However output of the tools can show only information of dozens of packets at once (tcpdump, wireshark) OR coarse-grained summary (tcpstat). It's difficult to understand "what is happening in your network" when troubleshooting.

`tcpswarm` is designed by following concepts.

- **Summarize massive traffic**:
- **Provide Various Analysis**:

## Setup

Make sure to configure environment variable `$GOPATH` before installation and set your `$PATH` for command execution.

```bash
go get -u github.com/m-mizutani/tcpswarm/cli/tcpswarm
```

## Usage

### Examples

Capture from device `eth0`.

```
$ sudo tcpswarm -i eth0
```

Read packet data from a pcap file `dumpfile.pcap`.

```
$ tcpswarm -r dumpfile.pcap
```

### Options

- `-r`: Specify a pcap format file to read saved packet data.
- `-i`: Specify a network interface to capture packets.
- `-l`, `--interval`: Set interval to output result by float number.
- `-m`, `--module`: Specify analyzing module from following list. This option can be put multiple times.
  - `session`: Show number of TCP/UDP sessions
  - `DistPktSize`: Show latest packet size distributions during interval and 9 previous distribution also.

## License

The 2-Clause BSD License.
