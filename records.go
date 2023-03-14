package records

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"
	"github.com/coredns/coredns/plugin/pkg/fall"

	"github.com/miekg/dns"
)

const maxCnameStackDepth = 10

// Records is the plugin handler.
type Records struct {
	origins  []string // for easy matching, these strings are the index in the map m.
	m        map[string][]dns.RR
	upstream *upstream.Upstream

	Next plugin.Handler
	Fall *fall.F
}

// ServeDNS implements the plugin.Handle interface.
func (re *Records) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	zone := plugin.Zones(re.origins).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(re.Name(), re.Next, ctx, w, r)
	}

	// New we should have some data for this zone, as we just have a list of RR, iterate through them, find the qname
	// and see if the qtype exists. If so reply, if not do the normal DNS thing and return either NXDOMAIN or NODATA.
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	nxdomain := true
	var soa dns.RR
	cnameStack := make(map[string]struct{}, 0)

resolveLoop:
	for _, r := range re.m[zone] {
		if _, ok := cnameStack[qname]; ok {
			log.Errorf("detected loop in CNAME chain, name [%s] already processed", qname)
			goto servfail
		}
		if len(cnameStack) > maxCnameStackDepth {
			log.Errorf("maximum CNAME stack depth of %d exceeded", maxCnameStackDepth)
			goto servfail
		}

		if r.Header().Rrtype == dns.TypeSOA && soa == nil {
			soa = r
		}
		if r.Header().Name == qname {
			nxdomain = false
			if r.Header().Rrtype == state.QType() || r.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, r)
			}
			if r.Header().Rrtype == dns.TypeCNAME {
				cnameStack[qname] = struct{}{}
				qname = r.(*dns.CNAME).Target
				if plugin.Zones(re.origins).Matches(qname) == "" {
					// if the CNAME target isn't a record in this zone, restart with upstream.
					msgs, err := re.upstream.Lookup(ctx, state, qname, state.QType())
					if err != nil {
						return dns.RcodeServerFailure, err
					}
					for _, ans := range msgs.Answer {
						m.Answer = append(m.Answer, ans)
					}
					break resolveLoop
				}
				goto resolveLoop
			}
		}
	}

	// handle NXDOMAIN, NODATA and normal response here.
	if nxdomain {
		if re.Fall.Through(qname) {
			return plugin.NextOrFailure(re.Name(), re.Next, ctx, w, r)
		}
		m.Rcode = dns.RcodeNameError
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
		w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	}

	if len(m.Answer) == 0 {
		if soa != nil {
			m.Ns = []dns.RR{soa}
		}
	}

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil

servfail:
	m.Rcode = dns.RcodeServerFailure
	m.Answer = nil
	if soa != nil {
		m.Ns = []dns.RR{soa}
	}
	w.WriteMsg(m)
	return dns.RcodeServerFailure, nil
}

// Name implements the plugin.Handle interface.
func (re *Records) Name() string { return "records" }

// New returns a pointer to a new and intialized Records.
func New() *Records {
	re := &Records{
		Fall: &fall.F{},
		m: make(map[string][]dns.RR),
		upstream: upstream.New(),
	}
	return re
}
