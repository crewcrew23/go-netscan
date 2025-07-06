package types

import "github.com/google/gopacket"

type LayerTypeWrapper struct {
	Layer *gopacket.LayerType
	Type  string
}
