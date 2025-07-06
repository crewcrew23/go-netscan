package main

import (
	"fmt"
	"log"

	"github.com/crewcrew23/go-netscan/internal/util"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	device := util.SelectInterface()
	fmt.Printf("you enter %s", device)

	conn, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(conn, conn.LinkType())
	for packet := range packetSource.Packets() {
		util.PrintPacketData(packet)
	}

}
