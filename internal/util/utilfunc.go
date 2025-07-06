package util

import (
	"fmt"
	"log"
	"strings"

	"github.com/crewcrew23/go-netscan/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SelectInterface() string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for i, v := range devs {
		fmt.Println("=====================================")
		fmt.Printf(" Interface #%d\n", i)
		fmt.Println("=====================================")
		fmt.Printf(" Name          : %s\n", v.Name)
		fmt.Printf(" Addresses     :\n")
		for _, addr := range v.Addresses {
			fmt.Printf("   - %s\n", addr.IP)
		}
		fmt.Printf(" Description   : %s\n", v.Description)
		fmt.Println()
	}

	var number int
	fmt.Println("Enter a number of interface")
	fmt.Scanf("%d", &number)

	return devs[number].Name
}

func PrintPacketData(packet gopacket.Packet, filterLayer *types.LayerTypeWrapper) {
	show := false

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if filterLayer != nil && *filterLayer.Layer == ethLayer.LayerType() {
			show = true
			fmt.Println("====== New Packet ======")
			eth, _ := ethLayer.(*layers.Ethernet)
			fmt.Printf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
		}
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if filterLayer != nil && *filterLayer.Layer == ipLayer.LayerType() {
			show = true
			fmt.Println("====== New Packet ======")
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("IPv4: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
		}
	}

	// TCP Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if filterLayer != nil && *filterLayer.Layer == tcpLayer.LayerType() {
			tcp, _ := tcpLayer.(*layers.TCP)

			if filterLayer.Type == "http" {
				if tcp.SrcPort == 80 || tcp.DstPort == 80 || tcp.SrcPort == 443 || tcp.DstPort == 443 {
					appLayer := packet.ApplicationLayer()
					if appLayer != nil {
						payload := appLayer.Payload()
						if isHttpPayload(payload) {
							fmt.Println("====== New Packet ======")
							fmt.Printf("TCP: %s:%d -> %s:%d\n", packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcp.DstPort)
							fmt.Println(string(payload))
						}
					}
				}
			} else {
				show = true
				fmt.Println("====== New Packet ======")
				fmt.Printf("TCP: %d -> %d | Flags: %s\n", tcp.SrcPort, tcp.DstPort, PintTCPFlags(packet))
			}
		}

	}

	// UDP Layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if filterLayer != nil && *filterLayer.Layer == udpLayer.LayerType() {
			show = true
			fmt.Println("====== New Packet ======")
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
		}
	}

	// ICMP Layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if filterLayer != nil && *filterLayer.Layer == icmpLayer.LayerType() {
			show = true
			fmt.Println("====== New Packet ======")
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("ICMPv4: TypeCode=%d Code=%d ID=%d Seq=%d \n",
				icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq)
		}

	}

	// Payload (if exists)
	if show {
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if len(payload) > 0 {
				PrettyPrintPayload(payload)
			}
		}

		if errLayer := packet.ErrorLayer(); errLayer != nil {
			fmt.Printf("Decoding error: %v\n", errLayer.Error())
		}

		fmt.Printf("=========================\n")
	}

}

func PrettyPrintPayload(payload []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(payload); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(payload) {
			end = len(payload)
		}
		line := payload[i:end]

		//HEX
		for _, b := range line {
			fmt.Printf("%02X", b)
		}

		for j := len(line); j < bytesPerLine; j++ {
			fmt.Print(" ")
		}
		fmt.Print(" | ")

		//ASCII
		for _, b := range line {
			if b > 32 && b < 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}

func isHttpPayload(payload []byte) bool {
	s := strings.ToUpper(string(payload))
	return strings.HasPrefix(s, "GET ") ||
		strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") ||
		strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "HEAD ") ||
		strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "HTTP/")
}

func PintTCPFlags(packet gopacket.Packet) string {
	flags := ""
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		if tcp.FIN {
			flags += "FIN "
		}

		if tcp.SYN {
			flags += "SYN "
		}

		if tcp.RST {
			flags += "RST "
		}

		if tcp.PSH {
			flags += "PSH "
		}

		if tcp.ACK {
			flags += "ACK "
		}

		if tcp.URG {
			flags += "URG "
		}

		if tcp.ECE {
			flags += "ECE "
		}

		if tcp.CWR {
			flags += "CWR "
		}

		if tcp.NS {
			flags += "NS "
		}
	}

	return flags
}
