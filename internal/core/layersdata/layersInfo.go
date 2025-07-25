package layersdata

import (
	"fmt"
	"time"

	"github.com/crewcrew23/go-netscan/internal/core/layersdata/layersutil"
	"github.com/crewcrew23/go-netscan/internal/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func PrintEthernetLayerData(packet gopacket.Packet, ethLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper, speed int32) bool {
	if filterLayer != nil && *filterLayer.Layer == ethLayer.LayerType() {
		fmt.Println("====== New Packet ======")
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet: %s -> %s | Type: %s\n", eth.SrcMAC, eth.DstMAC, eth.EthernetType)
		layersutil.PrintPayload(packet)
		fmt.Printf("=========================\n")
		time.Sleep(time.Millisecond * time.Duration(speed))
		return true

	}
	return false
}

func PrintIPLayerData(packet gopacket.Packet, ipLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper, speed int32) bool {
	if filterLayer != nil && *filterLayer.Layer == ipLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("IPv4: %s -> %s | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)
			layersutil.PrintPayload(packet)
		})
		time.Sleep(time.Millisecond * time.Duration(speed))
		return true

	}
	return false
}

func PrintTCPLayerData(packet gopacket.Packet, tcpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper, speed int32) bool {
	if filterLayer != nil && *filterLayer.Layer == tcpLayer.LayerType() {
		var payload []byte
		tcp, _ := tcpLayer.(*layers.TCP)
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload = appLayer.Payload()
		}

		if filterLayer.Type == "http" {
			if tcp.SrcPort == 80 ||
				tcp.DstPort == 80 ||
				tcp.SrcPort == 443 ||
				tcp.DstPort == 443 ||
				tcp.SrcPort == 8080 ||
				tcp.DstPort == 8080 ||
				layersutil.IsHttpPayload(payload) {

				layersutil.WrapPacketOutput(func() {
					fmt.Printf("HTTP or HTTPS: %s:%d -> %s:%d\n", packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort, packet.NetworkLayer().NetworkFlow().Dst().String(), tcp.DstPort)
					layersutil.PrintHttpPayload(payload)
				})
				time.Sleep(time.Millisecond * time.Duration(speed))
				return true

			}
		} else {
			layersutil.WrapPacketOutput(func() {
				fmt.Printf("TCP: %d -> %d | Flags: %s\n", tcp.SrcPort, tcp.DstPort, layersutil.PrintTCPFlags(packet))
				layersutil.PrintPayload(packet)
			})
			time.Sleep(time.Millisecond * time.Duration(speed))
			return true

		}
	}
	return false
}

func PrintUDPLayerData(packet gopacket.Packet, udpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper, speed int32) bool {
	if filterLayer != nil && *filterLayer.Layer == udpLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
			layersutil.PrintPayload(packet)
		})
		time.Sleep(time.Millisecond * time.Duration(speed))
		return true

	}
	return false
}

func PrintICMPLayerData(packet gopacket.Packet, icmpLayer gopacket.Layer, filterLayer *types.LayerTypeWrapper, speed int32) bool {
	if filterLayer != nil && *filterLayer.Layer == icmpLayer.LayerType() {
		layersutil.WrapPacketOutput(func() {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("ICMPv4: TypeCode=%d Code=%d ID=%d Seq=%d \n",
				icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Id, icmp.Seq)
			layersutil.PrintPayload(packet)
		})
		time.Sleep(time.Millisecond * time.Duration(speed))
		return true

	}
	return false
}
