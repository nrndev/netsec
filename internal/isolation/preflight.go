package isolation

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Addrs is an object (a pod or node, named for messages) and its IP addresses.
type Addrs struct {
	Name string
	IPs  []string
}

// OutsideRange returns "name (ip, ip)" for each object that has an address outside every
// range. Only addresses of a family that has a range count: with no range for a family there
// is no ipBlock for it, so such an address cannot match one. An address that does not parse
// counts as outside, so it shows up instead of hiding.
func OutsideRange(objs []Addrs, ranges []string) ([]string, error) {
	return filterRange(objs, ranges, nil, false)
}

// InRange returns "name (ip, ip)" for each object that has an address inside a range and
// not inside any covered block (addresses that are already allowed on purpose).
func InRange(objs []Addrs, ranges, covered []string) ([]string, error) {
	return filterRange(objs, ranges, covered, true)
}

// filterRange lists the objects with addresses whose "inside a range" answer equals inside.
func filterRange(objs []Addrs, ranges, covered []string, inside bool) ([]string, error) {
	skip, err := parsePrefixes(covered)
	if err != nil {
		return nil, err
	}
	prefixes, err := parsePrefixes(ranges)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range objs {
		var hits []string
		for _, s := range o.IPs {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				if !inside {
					hits = append(hits, s)
				}
				continue
			}
			ip = ip.Unmap()
			contains := func(p netip.Prefix) bool { return p.Contains(ip) }
			in := slices.ContainsFunc(prefixes, contains)
			switch {
			case inside && in && !slices.ContainsFunc(skip, contains):
				hits = append(hits, s)
			case !inside && !in && slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Addr().Is4() == ip.Is4() }):
				hits = append(hits, s)
			}
		}
		if len(hits) > 0 {
			out = append(out, fmt.Sprintf("%s (%s)", o.Name, strings.Join(hits, ", ")))
		}
	}
	return out, nil
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q is not valid: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}
