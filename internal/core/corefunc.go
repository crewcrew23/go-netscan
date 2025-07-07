package core

import (
	"fmt"
	"log"

	"github.com/crewcrew23/go-netscan/internal/core/layersdata"
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

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		layersdata.PrintEthernetLayerData(packet, ethLayer, filterLayer)
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		layersdata.PrintIPLayerData(packet, ipLayer, filterLayer)
	}

	// TCP Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		layersdata.PrintTCPLayerData(packet, tcpLayer, filterLayer)
	}

	// UDP Layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		layersdata.PrintUDPLayerData(packet, udpLayer, filterLayer)
	}

	// ICMP Layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		layersdata.PrintICMPLayerData(packet, icmpLayer, filterLayer)
	}
}
