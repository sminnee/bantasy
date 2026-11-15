package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// maxRDAPBody is 1 MiB. A real RDAP IP record is a few KiB.
const maxRDAPBody = 1 << 20

// rdapClient asks RDAP who holds an IP address.
type rdapClient struct {
	http *http.Client
	// base is the redirector, such as https://rdap.org.
	base string
	// registries are the RDAP base URLs by the prefix of an ARIN ERX
	// record name, such as "RIPE".
	registries map[string]string
}

// defaultRDAPClient asks rdap.org, and follows an ARIN ERX record to the
// registry that manages the block.
func defaultRDAPClient() rdapClient {
	return rdapClient{
		http: &http.Client{Timeout: 10 * time.Second},
		base: "https://rdap.org",
		registries: map[string]string{
			"RIPE":    "https://rdap.db.ripe.net",
			"APNIC":   "https://rdap.apnic.net",
			"AFRINIC": "https://rdap.afrinic.net",
			"LACNIC":  "https://rdap.lacnic.net/rdap",
		},
	}
}

// network is the address block that one RDAP record covers.
type network struct {
	url, name, country, org, abuse string
	cidrs                          []netip.Prefix
}

type rdapIP struct {
	Name         string       `json:"name"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Country      string       `json:"country"`
	Entities     []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	VcardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

// lookup returns the address block of addr. When the record is an ARIN
// ERX record, it asks the named registry once more.
func (c rdapClient) lookup(addr netip.Addr) (*network, error) {
	rec, url, err := c.get(c.base + "/ip/" + addr.String())
	if err != nil {
		return nil, err
	}

	if reg, ok := erxRegistry(rec.Name); ok {
		if base, ok := c.registries[reg]; ok {
			rec, url, err = c.get(base + "/ip/" + addr.String())
			if err != nil {
				return nil, err
			}
		}
	}

	start, err1 := netip.ParseAddr(rec.StartAddress)
	end, err2 := netip.ParseAddr(rec.EndAddress)

	var cidrs []netip.Prefix
	if err1 == nil && err2 == nil {
		cidrs = rangeCIDRs(start, end)
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("%s: bad address range %q to %q", url, rec.StartAddress, rec.EndAddress)
	}

	return &network{
		url: url, name: rec.Name, country: rec.Country,
		org: orgOf(rec.Entities), abuse: abuseOf(rec.Entities), cidrs: cidrs,
	}, nil
}

// get fetches one RDAP IP record. It returns the URL after redirects.
func (c rdapClient) get(url string) (*rdapIP, string, error) {
	// url is a fixed base and a parsed address; the client timeout bounds
	// the request.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil) //nolint:gosec // see above
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "bantasy-cli")

	resp, err := c.http.Do(req) //nolint:gosec // see above
	if err != nil {
		return nil, "", err
	}

	defer func() { _ = resp.Body.Close() }()

	final := resp.Request.URL.String()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: HTTP %s", final, resp.Status)
	}

	var rec rdapIP
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRDAPBody)).Decode(&rec); err != nil {
		return nil, "", fmt.Errorf("%s: %w", final, err)
	}

	return &rec, final, nil
}

// erxRegistry returns the registry prefix of an ARIN ERX record name, such
// as "RIPE" for RIPE-ERX-158-173-0-0.
func erxRegistry(name string) (string, bool) {
	reg, _, ok := strings.Cut(name, "-ERX")
	return reg, ok && reg != ""
}

// orgOf is the vCard fn of the registrant entity, else of the first entity.
func orgOf(ents []rdapEntity) string {
	for _, e := range ents {
		if hasRole(e, "registrant") {
			return vcardField(e.VcardArray, "fn")
		}
	}

	if len(ents) > 0 {
		return vcardField(ents[0].VcardArray, "fn")
	}

	return ""
}

// abuseOf is the vCard email of the first abuse entity, at any depth.
func abuseOf(ents []rdapEntity) string {
	for _, e := range ents {
		if hasRole(e, "abuse") {
			if v := vcardField(e.VcardArray, "email"); v != "" {
				return v
			}
		}

		if v := abuseOf(e.Entities); v != "" {
			return v
		}
	}

	return ""
}

func hasRole(e rdapEntity, role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}

	return false
}

// vcardField returns the first non-empty text value of property name in a
// jCard, ["vcard", [[name, params, type, value], ...]], or "" when none.
func vcardField(raw json.RawMessage, name string) string {
	var card []json.RawMessage
	if err := json.Unmarshal(raw, &card); err != nil || len(card) < 2 {
		return ""
	}

	var props [][]json.RawMessage
	if err := json.Unmarshal(card[1], &props); err != nil {
		return ""
	}

	for _, p := range props {
		var key, value string
		if len(p) < 4 || json.Unmarshal(p[0], &key) != nil || key != name {
			continue
		}

		if json.Unmarshal(p[3], &value) == nil && value != "" {
			return value
		}
	}

	return ""
}

// rangeCIDRs splits the range start to end, both included, into the
// fewest CIDRs. It returns nil for a bad range, which includes a zone:
// a prefix drops the zone, so the loop would never reach end.
func rangeCIDRs(start, end netip.Addr) []netip.Prefix {
	if start.Is4() != end.Is4() || end.Less(start) || start.Zone() != "" || end.Zone() != "" {
		return nil
	}

	var out []netip.Prefix

	for {
		// The widest prefix that starts at start and ends at or before end.
		var p netip.Prefix

		for bits := 0; bits <= start.BitLen(); bits++ {
			c := netip.PrefixFrom(start, bits).Masked()
			if c.Addr() == start && !end.Less(lastAddr(c)) {
				p = c
				break
			}
		}

		out = append(out, p)

		last := lastAddr(p)
		if last == end {
			return out
		}

		start = last.Next()
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As16()
	off := 128 - p.Addr().BitLen()

	for i := off + p.Bits(); i < 128; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}

	a := netip.AddrFrom16(b)
	if p.Addr().Is4() {
		return a.Unmap()
	}

	return a
}
