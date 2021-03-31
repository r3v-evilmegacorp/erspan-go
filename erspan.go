package main

import (
    "flag"
    "io"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func main() {
    sniffint := flag.String("sniff", "", "sniffing interface")
    injectint := flag.String("inject", "", "inject interface")

    flag.Parse()

    handle, err := pcap.OpenLive(*sniffint, 0, true, 0)
    if err != nil {
        handle, err = pcap.OpenOffline(*sniffint)
        if err != nil {
            panic(err)
        }
    }
    defer handle.Close()

    handleinj, err := pcap.OpenLive(*injectint, 0, true, 0)
    if err != nil {
        panic(err)
    }
    defer handleinj.Close()

    for {
        data, _, err := handle.ZeroCopyReadPacketData()
        if err != nil {
            if err == io.EOF {
                return
            }

            panic(err)
        }

        // Ethernet
        eth := layers.Ethernet{}
        err = eth.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
        if err != nil {
            continue
        }

        if eth.EthernetType != layers.EthernetTypeIPv4 {
            continue
        }

        // IP
        ip := layers.IPv4{}
        err = ip.DecodeFromBytes(eth.Payload, gopacket.NilDecodeFeedback)
        if err != nil {
            continue
        }

        if ip.Protocol != layers.IPProtocolGRE {
            continue
        }

        // GRE
        gre := layers.GRE{}
        err = gre.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback)
        if err != nil {
            continue
        }

        // Ethernet
        eth = layers.Ethernet{}
        err = eth.DecodeFromBytes(gre.Payload, gopacket.NilDecodeFeedback)
        if err != nil {
            continue
        }

        if eth.EthernetType != layers.EthernetTypeIPv4 {
            continue
        }

        // IP
        ip = layers.IPv4{}
        err = ip.DecodeFromBytes(eth.Payload, gopacket.NilDecodeFeedback)
        if err != nil {
            continue
        }

        buffer := gopacket.NewSerializeBuffer()
        gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
            &eth,
            gopacket.Payload(eth.Payload),
        )

        pkt := buffer.Bytes()

        err = handleinj.WritePacketData(pkt)
        if err != nil {
            panic(err)
        }
    }
}
