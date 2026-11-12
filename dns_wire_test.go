package main

import (
	"fmt"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSWireTransactionID(t *testing.T) {
	for _, id := range []uint16{0, 7, 65535} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			question, packet, err := newDNSQuestion("wire.example", dnsmessage.TypeA, id)
			if err != nil {
				t.Fatal(err)
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(packet); err != nil {
				t.Fatal(err)
			}
			if msg.ID != id || msg.Response || !msg.RecursionDesired || len(msg.Questions) != 1 || msg.Questions[0] != question {
				t.Fatalf("bad query: %+v", msg)
			}
			msg.Response = true
			msg.Answers = []dnsmessage.Resource{
				doHRecord("wire.example.", 3, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}),
				doHRecord("alias.example.", 20, &dnsmessage.AResource{A: [4]byte{203, 0, 113, 1}}),
				doHRecord("unrelated.example.", 0, &dnsmessage.AResource{A: [4]byte{203, 0, 113, 2}}),
			}
			packet, err = msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			answer, err := decodeDNSAnswer(packet, question, id)
			if err != nil || len(answer.addrs) != 1 || answer.addrs[0].String() != "203.0.113.1" || answer.ttl != 3 {
				t.Fatalf("answer=%+v err=%v", answer, err)
			}
			if _, err := decodeDNSAnswer(packet, question, id^1); err == nil {
				t.Fatal("accepted a different transaction ID")
			}
		})
	}
}
