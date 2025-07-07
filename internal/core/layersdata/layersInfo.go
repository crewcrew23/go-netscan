package layersdata

import (
	"fmt"

	"github.com/crewcrew23/go-netscan/internal/core/layersdata/layersutil"
	"github.com/crewcrew23/go-netscan/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PrintEthernetLayerData(ethLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == ethLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
		return true
	}
	return false
}

func PrintIPLayerData(ipLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == ipLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("IPv4: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
		return true
	}
	return false
}

func PrintTCPLayerData(packet gopacket.Packet, tcpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == tcpLayer.LayerType() {
		tcp, _ := tcpLayer.(*layers.TCP)

		if filterLayer.Type == "http" {
			if tcp.SrcPort == 80 || tcp.DstPort == 80 || tcp.SrcPort == 443 || tcp.DstPort == 443 {
				appLayer := packet.ApplicationLayer()
				if appLayer != nil {
					payload := appLayer.Payload()
					if layersutil.IsHttpPayload(payload) {
						fmt.Println("====== New Packet ======")
						fmt.Printf("TCP: %s:%d -> %s:%d\n", packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcp.DstPort)
						fmt.Println(string(payload))
						return true
					}
				}
			}
		} else {
			fmt.Println("====== New Packet ======")
			fmt.Printf("TCP: %d -> %d | Flags: %s\n", tcp.SrcPort, tcp.DstPort, layersutil.PintTCPFlags(packet))
			return true
		}
	}
	return false
}

func PrintUDPLayerData(udpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == udpLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
		return true
	}
	return false
}

func PrintICMPLayerData(icmpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == icmpLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("ICMPv4: TypeCode=%d Code=%d ID=%d Seq=%d \n",
			icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq)
		return true
	}
	return false
}
