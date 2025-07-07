package layersdata

import (
	"fmt"

	"github.com/crewcrew23/go-netscan/internal/core/layersdata/layersutil"
	"github.com/crewcrew23/go-netscan/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PrintEthernetLayerData(packet gopacket.Packet, ethLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == ethLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
		layersutil.PrintPayload(packet)
		fmt.Printf("=========================\n")
		return true
	}
	return false
}

func PrintIPLayerData(packet gopacket.Packet, ipLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == ipLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("IPv4: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
			layersutil.PrintPayload(packet)
		})
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
						layersutil.WrapPacketOutput(func() {
							fmt.Printf("TCP: %s:%d -> %s:%d\n", packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcp.DstPort)
							fmt.Println(string(payload)) //TODO: http paylaod
						})
						return true
					}
				}
			}
		} else {
			layersutil.WrapPacketOutput(func() {
				fmt.Printf("TCP: %d -> %d | Flags: %s\n", tcp.SrcPort, tcp.DstPort, layersutil.PirntTCPFlags(packet))
				layersutil.PrintPayload(packet)
			})
			return true
		}
	}
	return false
}

func PrintUDPLayerData(packet gopacket.Packet, udpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == udpLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
			layersutil.PrintPayload(packet)
		})
		return true
	}
	return false
}

func PrintICMPLayerData(packet gopacket.Packet, icmpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper) bool {
	if filterLayer != nil && *filterLayer.Layer == icmpLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("ICMPv4: TypeCode=%d Code=%d ID=%d Seq=%d \n",
				icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq)
			layersutil.PrintPayload(packet)
		})
		return true
	}
	return false
}
