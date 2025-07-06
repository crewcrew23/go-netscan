package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/crewcrew23/go-netscan/internal/util"
	"github.com/urfave/cli/v3"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	cmd := &cli.Command{
		Name: "go-netscan",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "i",
				Value:    "",
				Usage:    "name of network interface",
				Required: false,
			},

			&cli.BoolFlag{
				Name:     "find-interfaces",
				Usage:    "finds all available network interfaces",
				Required: false,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			netInterface := c.String("i")
			findInterfaces := c.Bool("find-interfaces")

			if !findInterfaces && netInterface == "" {
				return errors.New("at least 1 flag is required")
			}

			if findInterfaces {
				device := util.SelectInterface()
				start(device)
				return nil
			}

			start(netInterface)
			return nil

		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
	}
}

func start(netInterface string) {
	conn, err := pcap.OpenLive(netInterface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(conn, conn.LinkType())
	for packet := range packetSource.Packets() {
		util.PrintPacketData(packet)
	}
}
