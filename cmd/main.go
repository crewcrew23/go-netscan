package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/crewcrew23/go-netscan/internal/types"
	"github.com/crewcrew23/go-netscan/internal/util"
	"github.com/urfave/cli/v3"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	cmd := &cli.Command{
		Name:  "go-netscan",
		Usage: "network scaner",
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

			&cli.StringFlag{
				Name: "f",
				Validator: func(s string) error {
					values := map[string]bool{
						"tcp":  true,
						"udp":  true,
						"icmp": true,
						"http": true,
						"ipv4": true,
						"eth":  true,
					}

					if _, exists := values[s]; !exists {
						sl := make([]string, 0, len(values))
						for k := range values {
							sl = append(sl, k)
						}

						return fmt.Errorf("-f can accept %v", sl)
					}
					return nil
				},
				Usage:    "show filtred trafic",
				Required: false,
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			netInterface := c.String("i")
			findInterfaces := c.Bool("find-interfaces")
			filter := c.String("f")

			if !findInterfaces && netInterface == "" {
				return errors.New("at least 1 flag is required")
			}

			if findInterfaces {
				device := util.SelectInterface()
				start(device, makeLayerType(filter))
				return nil
			}

			start(netInterface, makeLayerType(filter))
			return nil

		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
	}
}

func makeLayerType(filter string) *types.LayerTypeWrapper {
	var filterLayer *types.LayerTypeWrapper

	if filter == "tcp" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeTCP, Type: "tcp"}
	}

	if filter == "udp" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeUDP, Type: "udp"}
	}

	if filter == "icmp" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeICMPv4, Type: "icmp"}
	}

	if filter == "ipv4" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeIPv4, Type: "ipv4"}
	}

	if filter == "eth" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeEthernet, Type: "eth"}
	}

	if filter == "http" {
		filterLayer = &types.LayerTypeWrapper{Layer: &layers.LayerTypeTCP, Type: "http"}
	}

	return filterLayer
}

func start(netInterface string, filterLayer *types.LayerTypeWrapper) {
	conn, err := pcap.OpenLive(netInterface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(conn, conn.LinkType())
	for packet := range packetSource.Packets() {
		util.PrintPacketData(packet, filterLayer)
	}
}
