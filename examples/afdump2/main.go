package main

import (
	"flag"
	"log"

	"github.com/google/gopacket/afpacket2"
	"github.com/google/gopacket/dumpcommand"
	"github.com/google/gopacket/examples/util"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tpVersion = flag.Int("tv", int(afpacket2.TPacketVersion3), "Tpacket Version")

func main() {
	defer util.Run()
	flag.Parse()
	log.Printf("Starting on interface %q\n", *iface)
	source, err := afpacket2.NewTPacket(
		afpacket2.OptInterface(*iface),
		afpacket2.OptFrameSize(*snaplen),
		afpacket2.OptBlockSize(*snaplen*128),
		afpacket2.OptTPacketVersion(*tpVersion),
		//afpacket2.OptPollTimeout(100),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()
	dumpcommand.Run(source)
}
