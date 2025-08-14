package common

import (
	"github.com/coreos/go-iptables/iptables"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"log"
)

const (
	CoreGid             = "3005"
	TproxyTableId       = "160"
	TproxyMarkId        = "0x1000000/0x1000000"
	DummyDevice         = "xdummy"
	DummyIp             = "fd01:5ca1:ab1e:8d97:497f:8b48:b9aa:85cd/128"
	DummyMarkId         = "0x2000000/0x2000000"
	DummyTableId        = "164"
	Tun2socksIPv4       = "10.10.12.1"
	Tun2socksIPv6       = "fd02:5ca1:ab1e:8d97:497f:8b48:b9aa:85cd"
	Tun2socksMTU        = 8500
	Tun2socksMultiQueue = false
	Tun2socksUdpMode    = "udp"
	TunTableId          = "168"
	TunMarkId           = "0x4000000/0x4000000"
)

var (
	Ipt, _    = iptables.NewWithProtocol(iptables.ProtocolIPv4)
	Ipt6, _   = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	IntraNet  = []string{"0.0.0.0/8", "10.0.0.0/8", "100.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"}
	IntraNet6 = []string{"::/128", "::1/128", "::ffff:0:0/96", "100::/64", "64:ff9b::/96", "2001::/32", "2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16", "fe80::/10", "ff00::/8"}
	UseDummy  = true
)

func init() {
	if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, address := range addrs {
				if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
					if ipnet.IP.To4() != nil {
						IntraNet = append(IntraNet, ipnet.IP.String())
					} else {
						UseDummy = false
						IntraNet6 = append(IntraNet6, ipnet.IP.String())
					}
				}
			}
		}
	}

func UpdateIntraNet(apList []string) {
	log.Printf("UpdateIntraNet: apList = %v", apList)
	out, err := exec.Command("ip", "addr").Output()
	if err != nil {
		return
	}

	interfaces := make(map[string][]string)
	var currentInterface string

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		r := regexp.MustCompile(`^\d+: ([^:@\s]+)`)
		matches := r.FindStringSubmatch(line)
		if len(matches) > 1 {
			currentInterface = matches[1]
		}

		if strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				if _, ipnet, err := net.ParseCIDR(fields[1]); err == nil {
					interfaces[currentInterface] = append(interfaces[currentInterface], ipnet.String())
				}
			}
		}
	}
	log.Printf("UpdateIntraNet: interfaces = %v", interfaces)

	for _, ap := range apList {
		wildcard := strings.HasSuffix(ap, "+")
		prefix := strings.TrimSuffix(ap, "+")
		for name, ips := range interfaces {
			if (wildcard && strings.HasPrefix(name, prefix)) || (!wildcard && name == prefix) {
				IntraNet = append(IntraNet, ips...)
			}
		}
	}
}
