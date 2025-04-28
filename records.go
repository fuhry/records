package records

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Records is the plugin handler.
type Records struct {
	origins []string // for easy matching, these strings are the index in the map m.
	m       map[string][]dns.RR

	Next plugin.Handler
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
	wcMatched := false
	var soa dns.RR
	for _, r := range re.m[zone] {
		if r.Header().Rrtype == dns.TypeSOA && soa == nil {
			soa = r
		}
		if r.Header().Name == qname {
			nxdomain = false
			if r.Header().Rrtype == state.QType() {
				m.Answer = append(m.Answer, r)
			}
		} else if !wcMatched {
			for _, wc := range Wildcards(qname) {
				if r.Header().Name == wc {
					// wildcard matched - copy the record because we need to mutate it for the
					// response
					newRecord, err := dns.NewRR(r.String())
					if err != nil {
						// failed to copy record
						break
					}

					nxdomain = false
					wcMatched = true

					newRecord.Header().Name = qname
					m.Answer = append(m.Answer, newRecord)
					break
				}
			}
		}
	}

	// handle NXDOMAIN, NODATA and normal response here.
	if nxdomain {
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
}

// Name implements the plugin.Handle interface.
func (re *Records) Name() string { return "records" }

// New returns a pointer to a new and intialized Records.
func New() *Records {
	re := new(Records)
	re.m = make(map[string][]dns.RR)
	return re
}

func Wildcards(name string) []string {
	parts := strings.Split(string(name), ".")
	wildcards := make([]string, len(parts))
	for i, _ := range parts {
		parts[i] = "*"
		wildcards[i] = strings.Join(parts[i:], ".")
	}
	return wildcards
}
