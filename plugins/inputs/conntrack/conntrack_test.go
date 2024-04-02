//go:build linux

package conntrack

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNfConntrackParse(t *testing.T) {
	fakeRow := []byte(`ipv4     2 udp      17 19 src=192.168.0.230 dst=8.8.8.8 sport=37421 dport=123 [UNREPLIED] src=8.8.8.8 dst=10.255.244.37 sport=123 dport=31224 mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 udp      17 19 src=192.168.0.181 dst=8.8.8.8 sport=56467 dport=123 src=8.8.8.8 dst=10.255.244.37 sport=123 dport=55189 mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 7 CLOSE src=192.168.0.72 dst=8.8.8.8 sport=28426 dport=443 src=8.8.8.8 dst=10.255.244.37 sport=443 dport=50394 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1 TIME_WAIT src=192.168.0.221 dst=8.8.8.8 sport=30596 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=47976 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1198 ESTABLISHED src=192.168.0.72 dst=8.8.8.8 sport=20162 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=1410 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 9 TIME_WAIT src=192.168.0.221 dst=8.8.8.8 sport=13396 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=48534 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1199 ESTABLISHED src=192.168.0.221 dst=8.8.8.8 sport=33444 dport=443 src=8.8.8.8 dst=10.255.244.37 sport=443 dport=6168 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1199 ESTABLISHED src=192.168.0.230 dst=8.8.8.8 sport=31540 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=22071 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 0 CLOSE src=192.168.0.221 dst=8.8.8.8 sport=46302 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=43508 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 7 TIME_WAIT src=192.168.0.19 dst=8.8.8.8 sport=14532 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=46470 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 4 TIME_WAIT src=192.168.0.221 dst=8.8.8.8 sport=11120 dport=80 src=8.8.8.8 dst=10.255.244.37 sport=80 dport=39246 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1191 ESTABLISHED src=192.168.0.221 dst=8.8.8.8 sport=55518 dport=443 src=8.8.8.8 dst=10.255.244.37 sport=443 dport=44639 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 1199 ESTABLISHED src=192.168.0.221 dst=8.8.8.8 sport=10934 dport=443 src=8.8.8.8 dst=10.255.244.37 sport=443 dport=31644 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
ipv4     2 tcp      6 8 CLOSE src=192.168.0.221 dst=8.8.8.8 sport=49746 dport=5454 src=8.8.8.8 dst=10.255.244.37 sport=5454 dport=44524 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2`)

	expected := map[string]int64{
		"tcp_close":       2,
		"tcp_established": 5,
		"tcp_time_wait":   4,
		"udp_unreplied":   1,
	}
	nf := newNfConntrack(bytes.NewReader(fakeRow))
	if !assert.ObjectsAreEqualValues(expected, nf.counters) {
		t.Error("Invalid result in the parser")
	}
}
