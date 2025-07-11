package layersutil

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func WrapPacketOutput(fn func()) {
	fmt.Println("====== New Packet ======")
	fn()
	fmt.Printf("=========================\n")
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

func PrintHttpPayload(payload []byte) {
	if len(payload) == 0 {
		return
	}

	s := string(payload)
	lower := strings.ToLower(s)
	textualTypes := []string{
		"content-type: text",
		"content-type: application/json",
		"content-type: application/x-www-form-urlencoded",
		"content-type: application/graphql",
		"content-type: application/x-yaml",
		"content-type: application/xml",
		"content-type: text/xml",
	}

	for _, h := range textualTypes {
		if strings.Contains(lower, h) {
			fmt.Println(s)
			return
		}
	}

	if utf8.Valid(payload) {
		fmt.Println(string(payload))
		return
	}

	PrettyPrintPayload(payload)
}

func PrettyPrintPayload(payload []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(payload); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(payload) {
			end = len(payload)
		}
		line := payload[i:end]

		// HEX
		for _, b := range line {
			fmt.Printf("%02X ", b)
		}
		// padding
		for j := len(line); j < bytesPerLine; j++ {
			fmt.Print("   ")
		}
		fmt.Print("| ")

		// ASCII
		for _, b := range line {
			if b >= 32 && b < 127 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}
}

func IsHttpPayload(payload []byte) bool {
	if payload == nil {
		return false
	}
	s := strings.ToUpper(string(payload))
	httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "HTTP/"}
	for _, method := range httpMethods {
		if strings.HasPrefix(s, method) {
			return true
		}
	}
	return false
}

func PrintTCPFlags(packet gopacket.Packet) string {
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
