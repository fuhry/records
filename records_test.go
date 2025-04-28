package records

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/coredns/caddy"
	"github.com/miekg/dns"
)

func TestLookup(t *testing.T) {
	const input = `
records {
        example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600
        example.org.   60  IN MX 10 mx.example.org.
        mx.example.org. 60 IN A  127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCases {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCases = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Rcode: dns.RcodeNameError,
		Qname: "bla.example.org.", Qtype: dns.TypeA,
		Ns: []dns.RR{
			test.SOA("example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600"),
		},
	},
	{
		Qname: "mx.example.org.", Qtype: dns.TypeAAAA,
		Ns: []dns.RR{
			test.SOA("example.org.   60  IN SOA ns.icann.org. noc.dns.icann.org. 2020091001 7200 3600 1209600 3600"),
		},
	},
}

func TestLookupNoSOA(t *testing.T) {
	const input = `
records {
        example.org.   60  IN MX 10 mx.example.org.
        mx.example.org. 60 IN A  127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesNoSOA {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesNoSOA = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Rcode: dns.RcodeNameError,
		Qname: "bla.example.org.", Qtype: dns.TypeA,
	},
	{
		Qname: "mx.example.org.", Qtype: dns.TypeAAAA,
	},
}

func TestLookupMultipleOrigins(t *testing.T) {
	const input = `
records example.org example.net {
        @ 60  IN MX 10 mx
        mx 60 IN A  127.0.0.1
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesMultipleOrigins {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesMultipleOrigins = []test.Case{
	{
		Qname: "mx.example.org.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.org. 60	IN	A 127.0.0.1"),
		},
	},
	{
		Qname: "mx.example.net.", Qtype: dns.TypeA,
		Answer: []dns.RR{
			test.A("mx.example.net. 60	IN	A 127.0.0.1"),
		},
	},
}

func TestWildcard(t *testing.T) {
	const input = `
records {
		*.example.com.	60	IN	A	127.0.0.1
		*.subdomain.example.com.	60	IN	A	127.0.0.2
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesWildcard {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesWildcard = []test.Case{
	{
		Qname: "a.example.com",
		Answer: []dns.RR{
			test.A("a.example.com. 60 IN A 127.0.0.1"),
		},
	},
	{
		Qname: "a.subdomain.example.com",
		Answer: []dns.RR{
			test.A("a.subdomain.example.com. 60 IN A 127.0.0.2"),
		},
	},
}

func TestWildcardMultipleOrigins(t *testing.T) {
	const input = `
records example.com example.net {
		*	60	IN	A	127.0.0.1
		*.subdomain	60	IN	A	127.0.0.2
}
`

	c := caddy.NewTestController("dns", input)
	re, err := recordsParse(c)
	if err != nil {
		t.Fatal(err)
	}

	for i, tc := range testCasesWildcard {
		m := tc.Msg()

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := re.ServeDNS(context.Background(), rec, m)
		if err != nil {
			t.Errorf("Test %d, expected no error, got %v", i, err)
			return
		}

		if rec.Msg.Rcode != tc.Rcode {
			t.Errorf("Test %d, expected rcode is %d, but got %d", i, tc.Rcode, rec.Msg.Rcode)
			return
		}

		if resp := rec.Msg; rec.Msg != nil {
			if err := test.SortAndCheck(resp, tc); err != nil {
				t.Errorf("Test %d: %v", i, err)
			}
		}
	}
}

var testCasesWildcardMultipleOrigins = []test.Case{
	{
		Qname: "a.example.com",
		Answer: []dns.RR{
			test.A("a.example.com. 60 IN A 127.0.0.1"),
		},
	},
	{
		Qname: "a.subdomain.example.com",
		Answer: []dns.RR{
			test.A("a.subdomain.example.com. 60 IN A 127.0.0.2"),
		},
	},
	{
		Qname: "a.example.net",
		Answer: []dns.RR{
			test.A("a.example.net. 60 IN A 127.0.0.1"),
		},
	},
	{
		Qname: "a.subdomain.example.net",
		Answer: []dns.RR{
			test.A("a.subdomain.example.net. 60 IN A 127.0.0.2"),
		},
	},
}

func TestWildcardListGeneration(t *testing.T) {
	type testCase struct {
		in     string
		expect []string
	}

	testCases := []*testCase{
		{
			in:     "example.com",
			expect: []string{"*.com", "*"},
		},
		{
			in:     "foo.example.com",
			expect: []string{"*.example.com", "*.com", "*"},
		},
		{
			in:     "bar.foo.example.com",
			expect: []string{"*.foo.example.com", "*.example.com", "*.com", "*"},
		},
	}

	for _, tc := range testCases {
		out := Wildcards(tc.in)
		if !slices.Equal[[]string, string](tc.expect, out) {
			fmt.Printf(
				"Wildcard candidate name generation test failed:\nexpect: %+v\ngot:    %+v\n",
				tc.expect, out)
			t.Fail()
		}
	}
}
