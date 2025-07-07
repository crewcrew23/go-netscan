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
	show := false

	// Ethernet Layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		show = layersdata.PrintEthernetLayerData(ethLayer, filterLayer)
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		show = layersdata.PrintIPLayerData(ipLayer, filterLayer)
	}

	// TCP Layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		show = layersdata.PrintTCPLayerData(packet, tcpLayer, filterLayer)
	}

	// UDP Layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		show = layersdata.PrintUDPLayerData(udpLayer, filterLayer)
	}

	// ICMP Layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		show = layersdata.PrintICMPLayerData(icmpLayer, filterLayer)
	}

	// Payload (if exists)
	if show {
		PrintPayload(packet)
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

func PrintPayload(packet gopacket.Packet) {
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
}
