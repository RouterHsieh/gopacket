package main

import (
	"flag"
	"log"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/dumpcommand"
	"github.com/google/gopacket/examples/util"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")

func main() {
	defer util.Run()
	log.Printf("Starting on interface %q\n", *iface)
	source, err := afpacket.NewTPacket(
		afpacket.OptInterface(*iface),
		afpacket.OptFrameSize(*snaplen),
		afpacket.OptBlockSize(*snaplen*128),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()
	dumpcommand.Run(source)
}
