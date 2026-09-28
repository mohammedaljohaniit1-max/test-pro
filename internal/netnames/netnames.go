// Package netnames resolves the host names of devices on the local network.
//
// Three independent, read-only lookups are used, in order of how
// authoritative they are on a home / office LAN:
//
//   - NetBIOS Node Status (NBSTAT, RFC 1002 §4.2.18): a single UDP datagram
//     to <ip>:137 asking the host for its registered names. Windows PCs,
//     Samba servers and most NAS boxes answer with their computer name and
//     workgroup / domain.
//   - Multicast DNS reverse lookup (RFC 6762): a PTR query for
//     <d.c.b.a>.in-addr.arpa sent unicast to <ip>:5353 (the "legacy unicast"
//     response path of §6.7). Apple devices, printers, Chromecasts, Linux
//     hosts running Avahi and most IoT gear answer with "<name>.local".
//   - Conventional reverse DNS (PTR) via the system resolver — covers hosts
//     registered by the router's DHCP server.
//
// Only the target host is contacted; nothing is broadcast. All packet
// building and parsing is platform-independent and unit-tested.
package netnames

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result holds every name found for one address.
type Result struct {
	IP          string            `json:"ip"`
	Name        string            `json:"name,omitempty"`   // best name
	Source      string            `json:"source,omitempty"` // netbios, mdns, dns
	Workgroup   string            `json:"workgroup,omitempty"`
	Names       map[string]string `json:"names,omitempty"`
	NBMAC       string            `json:"nbMac,omitempty"` // MAC reported inside the NBSTAT reply
	Model       string            `json:"model,omitempty"`
	ModelSource string            `json:"modelSource,omitempty"`
	Maker       string            `json:"maker,omitempty"`
}

// Resolver performs the lookups. The zero value is not usable; use New.
type Resolver struct {
	Timeout    time.Duration // per protocol (default 900 ms)
	NetBIOS    bool
	MDNS       bool
	DNS        bool
	SSDP       bool
	AppleTXT   bool
	LookupAddr func(ctx context.Context, addr string) ([]string, error)
}

// New returns a resolver with all three methods enabled.
func New() *Resolver {
	return &Resolver{Timeout: 900 * time.Millisecond, NetBIOS: true, MDNS: true, DNS: true, SSDP: true, AppleTXT: true, LookupAddr: net.DefaultResolver.LookupAddr}
}

// Resolve queries ip with every enabled method concurrently and returns the
// merged result. Preference: NetBIOS computer name, then mDNS, then DNS.
func (r *Resolver) Resolve(ctx context.Context, ip string) Result {
	res := Result{IP: ip, Names: map[string]string{}}
	p := net.ParseIP(ip)
	if p == nil {
		return res
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	set := func(src, name string) {
		if name == "" {
			return
		}
		mu.Lock()
		res.Names[src] = name
		mu.Unlock()
	}
	if r.NetBIOS && p.To4() != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if nb, err := QueryNBSTAT(ctx, ip, r.Timeout); err == nil {
				set("netbios", nb.Name)
				mu.Lock()
				res.Workgroup, res.NBMAC = nb.Group, nb.MAC
				mu.Unlock()
			}
		}()
	}
	if r.MDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := QueryMDNSPTR(ctx, ip, r.Timeout); err == nil {
				set("mdns", n)
			}
		}()
	}
	if r.SSDP && p.To4() != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			model, maker, name, err := QuerySSDP(ctx, ip, r.Timeout)
			if err == nil {
				mu.Lock()
				if res.Model == "" {
					res.Model, res.Maker, res.ModelSource = model, maker, "ssdp"
				}
				mu.Unlock()
				set("ssdp", name)
			}
		}()
	}
	if r.AppleTXT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, err := QueryAppleTXT(ctx, ip, r.Timeout); err == nil && code != "" {
				mu.Lock()
				res.Model, res.Maker, res.ModelSource = AppleModelName(code), "Apple", "bonjour-txt"
				mu.Unlock()
			}
		}()
	}
	if r.DNS && r.LookupAddr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 2*r.Timeout)
			defer cancel()
			if names, err := r.LookupAddr(c, ip); err == nil && len(names) > 0 {
				n := strings.TrimSuffix(names[0], ".")
				if n != "" && !strings.HasSuffix(n, ".in-addr.arpa") && !strings.HasSuffix(n, ".ip6.arpa") {
					set("dns", n)
				}
			}
		}()
	}
	wg.Wait()
	for _, src := range []string{"netbios", "mdns", "ssdp", "dns"} {
		if n := res.Names[src]; n != "" {
			res.Name, res.Source = n, src
			break
		}
	}
	if len(res.Names) == 0 {
		res.Names = nil
	}
	return res
}

// ---------------------------------------------------------------------------
// NetBIOS Node Status
// ---------------------------------------------------------------------------

// NBStat is the decoded NetBIOS node status.
type NBStat struct {
	Name  string   // unique <00> workstation name
	Group string   // group <00> name (workgroup / domain)
	All   []string // every name with its suffix, e.g. "DESKTOP-1<20>"
	MAC   string
}

// BuildNBSTAT builds a Node Status Request for the wildcard name "*".
func BuildNBSTAT(id uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0x00, 0x00) // flags: query
	b = append(b, 0, 1, 0, 0, 0, 0, 0, 0)
	// First-level encoded "*" padded with NULs to 16 bytes → 32 chars.
	b = append(b, 32)
	name := [16]byte{'*'}
	for _, c := range name {
		b = append(b, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	b = append(b, 0)
	b = append(b, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
	return b
}

// ErrBadReply is returned for malformed or unrelated responses.
var ErrBadReply = errors.New("netnames: malformed reply")

// ParseNBSTAT decodes a Node Status Response.
func ParseNBSTAT(pkt []byte, id uint16) (NBStat, error) {
	var st NBStat
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt) != id || pkt[2]&0x80 == 0 {
		return st, ErrBadReply
	}
	off := 12
	// Skip the answer RR name (may be a label sequence or a pointer).
	off, ok := skipName(pkt, off)
	if !ok || off+10 > len(pkt) {
		return st, ErrBadReply
	}
	if binary.BigEndian.Uint16(pkt[off:]) != 0x21 {
		return st, ErrBadReply
	}
	off += 10 // type, class, ttl, rdlength
	if off >= len(pkt) {
		return st, ErrBadReply
	}
	n := int(pkt[off])
	off++
	if off+n*18 > len(pkt) {
		return st, ErrBadReply
	}
	for i := 0; i < n; i++ {
		e := pkt[off+i*18 : off+i*18+18]
		name := strings.TrimRight(string(e[:15]), " \x00")
		suffix := e[15]
		flags := binary.BigEndian.Uint16(e[16:])
		group := flags&0x8000 != 0
		st.All = append(st.All, name+"<"+strings.ToUpper(strconv.FormatUint(uint64(suffix)|0x100, 16)[1:])+">")
		if suffix == 0x00 && !group && st.Name == "" && printable(name) {
			st.Name = name
		}
		if suffix == 0x00 && group && st.Group == "" && printable(name) {
			st.Group = name
		}
		if suffix == 0x20 && !group && st.Name == "" && printable(name) {
			st.Name = name
		}
	}
	off += n * 18
	if off+6 <= len(pkt) {
		mac := pkt[off : off+6]
		zero := true
		for _, x := range mac {
			if x != 0 {
				zero = false
			}
		}
		if !zero {
			parts := make([]string, 6)
			for i, x := range mac {
				parts[i] = strings.ToUpper(strconv.FormatUint(uint64(x)|0x100, 16)[1:])
			}
			st.MAC = strings.Join(parts, "-")
		}
	}
	if st.Name == "" {
		return st, ErrBadReply
	}
	return st, nil
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// QueryNBSTAT sends a node status request to ip:137 and waits for a reply.
func QueryNBSTAT(ctx context.Context, ip string, timeout time.Duration) (NBStat, error) {
	id := uint16(rand.Intn(0xffff))
	pkt, err := udpExchange(ctx, net.JoinHostPort(ip, "137"), BuildNBSTAT(id), timeout, func(b []byte) bool {
		return len(b) >= 2 && binary.BigEndian.Uint16(b) == id
	})
	if err != nil {
		return NBStat{}, err
	}
	return ParseNBSTAT(pkt, id)
}

// ---------------------------------------------------------------------------
// mDNS / DNS PTR
// ---------------------------------------------------------------------------

// ReverseName returns the in-addr.arpa / ip6.arpa name for ip.
func ReverseName(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return strconv.Itoa(int(v4[3])) + "." + strconv.Itoa(int(v4[2])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[0])) + ".in-addr.arpa"
	}
	const hx = "0123456789abcdef"
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hx[p[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hx[p[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

// BuildPTRQuery builds a DNS query for the PTR record of name.
func BuildPTRQuery(id uint16, name string) []byte {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 12, 0, 1) // PTR, IN
	return b
}

// ParsePTRReply returns the first PTR target in a DNS response.
func ParsePTRReply(pkt []byte, id uint16) (string, error) {
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt) != id || pkt[2]&0x80 == 0 {
		return "", ErrBadReply
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:]))
	an := int(binary.BigEndian.Uint16(pkt[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		if off, ok = skipName(pkt, off); !ok || off+4 > len(pkt) {
			return "", ErrBadReply
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		var ok bool
		if off, ok = skipName(pkt, off); !ok || off+10 > len(pkt) {
			return "", ErrBadReply
		}
		typ := binary.BigEndian.Uint16(pkt[off:])
		rdl := int(binary.BigEndian.Uint16(pkt[off+8:]))
		off += 10
		if off+rdl > len(pkt) {
			return "", ErrBadReply
		}
		if typ == 12 {
			name, ok := readName(pkt, off, 0)
			if !ok || name == "" {
				return "", ErrBadReply
			}
			return strings.TrimSuffix(name, "."), nil
		}
		off += rdl
	}
	return "", ErrBadReply
}

// QueryMDNSPTR asks ip's mDNS responder (unicast to port 5353) for its
// reverse-mapping name.
func QueryMDNSPTR(ctx context.Context, ip string, timeout time.Duration) (string, error) {
	id := uint16(rand.Intn(0xffff))
	q := BuildPTRQuery(id, ReverseName(ip))
	pkt, err := udpExchange(ctx, net.JoinHostPort(ip, "5353"), q, timeout, func(b []byte) bool {
		// Responders to legacy unicast queries echo the ID; some send ID 0.
		return len(b) >= 12 && b[2]&0x80 != 0
	})
	if err != nil {
		return "", err
	}
	if binary.BigEndian.Uint16(pkt) == 0 {
		binary.BigEndian.PutUint16(pkt, id)
	}
	return ParsePTRReply(pkt, id)
}

// AppleModelName maps exact machine identifiers; unknown identifiers remain
// unchanged rather than fabricating a product from an OUI. iPhone15,2 is
// iPhone 14 Pro (not 15 Pro); the 15 Pro is iPhone16,1.
func AppleModelName(code string) string {
	known := map[string]string{
		"iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
		"iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
		"iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
		"iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
		"MacBookAir10,1": "MacBook Air (M1)", "MacBookAir15,2": "MacBook Air (M3, 13-inch)",
		"AppleTV11,1": "Apple TV 4K (2nd generation)",
	}
	if s := known[code]; s != "" {
		return s
	}
	return code
}

// ParseAppleTXT walks DNS questions and all answer/additional records. TXT
// strings must be length-prefixed, bounded by RDLENGTH and owned by an Apple
// Bonjour service instance; arbitrary DNS bytes never become a device model.
func ParseAppleTXT(pkt []byte) (string, error) {
	if len(pkt) < 12 || pkt[2]&0x80 == 0 {
		return "", ErrBadReply
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:]))
	counts := int(binary.BigEndian.Uint16(pkt[6:])) + int(binary.BigEndian.Uint16(pkt[8:])) + int(binary.BigEndian.Uint16(pkt[10:]))
	if qd > 16 || counts > 128 {
		return "", ErrBadReply
	}
	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		off, ok = skipName(pkt, off)
		if !ok || off+4 > len(pkt) {
			return "", ErrBadReply
		}
		off += 4
	}
	for i := 0; i < counts; i++ {
		name, ok := readName(pkt, off, 0)
		if !ok {
			return "", ErrBadReply
		}
		off, ok = skipName(pkt, off)
		if !ok || off+10 > len(pkt) {
			return "", ErrBadReply
		}
		typ, rdl := binary.BigEndian.Uint16(pkt[off:]), int(binary.BigEndian.Uint16(pkt[off+8:]))
		off += 10
		if off+rdl > len(pkt) {
			return "", ErrBadReply
		}
		if typ == 16 && (strings.HasSuffix(strings.ToLower(name), "._airplay._tcp.local") || strings.HasSuffix(strings.ToLower(name), "._apple-mobdev2._tcp.local")) {
			for pos := off; pos < off+rdl; {
				l := int(pkt[pos])
				pos++
				if pos+l > off+rdl {
					return "", ErrBadReply
				}
				k, v, found := strings.Cut(string(pkt[pos:pos+l]), "=")
				pos += l
				if found && (strings.EqualFold(k, "model") || strings.EqualFold(k, "am") || strings.EqualFold(k, "md")) && len(v) > 0 && len(v) <= 80 {
					valid := true
					for _, c := range v {
						if c < 0x20 || c > 0x7e {
							valid = false
							break
						}
					}
					if valid {
						return v, nil
					}
				}
			}
		}
		off += rdl
	}
	return "", ErrBadReply
}

// QueryAppleTXT sends targeted legacy-unicast mDNS queries, not a network
// sweep. A responder may include TXT in the additional section of a PTR reply.
func QueryAppleTXT(ctx context.Context, ip string, timeout time.Duration) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", ErrBadReply
	}
	for _, service := range []string{"_apple-mobdev2._tcp.local", "_airplay._tcp.local"} {
		q := BuildPTRQuery(uint16(rand.Intn(0xffff)), service)
		pkt, err := udpExchange(ctx, net.JoinHostPort(ip, "5353"), q, timeout, func(b []byte) bool { return len(b) >= 12 && b[2]&0x80 != 0 })
		if err == nil {
			if code, err := ParseAppleTXT(pkt); err == nil {
				return code, nil
			}
			// TXT often needs a second question directed at the PTR instance.
			if instance, err := ParsePTRReply(pkt, binary.BigEndian.Uint16(pkt)); err == nil && strings.HasSuffix(strings.ToLower(instance), strings.ToLower(service)) {
				q = BuildPTRQuery(uint16(rand.Intn(0xffff)), instance)
				q[len(q)-3] = 16 // QTYPE TXT (instead of PTR 12)
				if reply, err := udpExchange(ctx, net.JoinHostPort(ip, "5353"), q, timeout, func(b []byte) bool { return len(b) >= 12 && b[2]&0x80 != 0 }); err == nil {
					if code, err := ParseAppleTXT(reply); err == nil {
						return code, nil
					}
				}
			}
		}
	}
	return "", ErrBadReply
}

// QuerySSDP asks only the known LAN host for its UPnP descriptor. LOCATION
// must point back to the same literal IP; redirects are disabled to avoid
// using discovery responses as a general-purpose SSRF proxy.
func QuerySSDP(ctx context.Context, ip string, timeout time.Duration) (model, maker, name string, err error) {
	if net.ParseIP(ip) == nil {
		return "", "", "", ErrBadReply
	}
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ip, "1900"))
	if err != nil {
		return "", "", "", err
	}
	c, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return "", "", "", err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	_, err = c.Write([]byte("M-SEARCH * HTTP/1.1\r\nHOST: " + net.JoinHostPort(ip, "1900") + "\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"))
	if err != nil {
		return "", "", "", err
	}
	buf := make([]byte, 4096)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return "", "", "", err
	}
	var location string
	for _, line := range strings.Split(string(buf[:n]), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			location = strings.TrimSpace(line[len("location:"):])
			break
		}
	}
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(ip)) || u.User != nil {
		return "", "", "", ErrBadReply
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", "", "", err
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", "", ErrBadReply
	}
	var doc struct {
		Device struct {
			Model        string `xml:"modelName"`
			Manufacturer string `xml:"manufacturer"`
			Friendly     string `xml:"friendlyName"`
		} `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return "", "", "", err
	}
	return strings.TrimSpace(doc.Device.Model), strings.TrimSpace(doc.Device.Manufacturer), strings.TrimSpace(doc.Device.Friendly), nil
}

func skipName(pkt []byte, off int) (int, bool) {
	for off < len(pkt) {
		l := int(pkt[off])
		switch {
		case l == 0:
			return off + 1, true
		case l&0xc0 == 0xc0:
			return off + 2, off+2 <= len(pkt)
		default:
			off += 1 + l
		}
	}
	return off, false
}

func readName(pkt []byte, off, depth int) (string, bool) {
	if depth > 8 {
		return "", false
	}
	var labels []string
	for off < len(pkt) {
		l := int(pkt[off])
		switch {
		case l == 0:
			return strings.Join(labels, "."), true
		case l&0xc0 == 0xc0:
			if off+1 >= len(pkt) {
				return "", false
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:]) & 0x3fff)
			rest, ok := readName(pkt, ptr, depth+1)
			if !ok {
				return "", false
			}
			if rest != "" {
				labels = append(labels, rest)
			}
			return strings.Join(labels, "."), true
		default:
			if off+1+l > len(pkt) {
				return "", false
			}
			labels = append(labels, string(pkt[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", false
}

func udpExchange(ctx context.Context, addr string, q []byte, timeout time.Duration, match func([]byte) bool) ([]byte, error) {
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if match(buf[:n]) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}
