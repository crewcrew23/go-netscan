package layersutil

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func IsHttpPayload(payload []byte) bool {
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
