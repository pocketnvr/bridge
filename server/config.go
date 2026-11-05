package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	FrigateURL   string
	WGPort       int
	PublicPort   int
	PublicHost   string
	WebPort      int
	UPnP         bool
	DataDir      string
	ClientNet    netip.Prefix
	AllowedHosts []string

	frigate     *url.URL
	forwardAddr string
	phoneIP     netip.Addr
	frigatePort uint16
	phoneURL    string
}

type haOptions struct {
	FrigateURL string `json:"frigate_url"`
	PublicHost string `json:"public_host"`
	WGPort     int    `json:"wg_port"`
	PublicPort int    `json:"public_port"`
	WebPort    int    `json:"web_port"`
	UPnP       *bool  `json:"upnp"`
	Allowed    string `json:"allowed_hosts"`
}

func LoadConfig() (*Config, error) {
	c := &Config{
		WGPort:    51820,
		WebPort:   8765,
		UPnP:      true,
		DataDir:   "/data",
		ClientNet: netip.MustParsePrefix("10.77.0.0/24"),
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		c.DataDir = v
	}

	addon := false
	if b, err := os.ReadFile(filepath.Join(c.DataDir, "options.json")); err == nil {
		addon = true
		var o haOptions
		if err := json.Unmarshal(b, &o); err != nil {
			return nil, fmt.Errorf("options.json: %w", err)
		}
		c.FrigateURL = o.FrigateURL
		c.PublicHost = o.PublicHost
		if o.WGPort > 0 {
			c.WGPort = o.WGPort
		}
		if o.PublicPort > 0 {
			c.PublicPort = o.PublicPort
		}
		if o.WebPort > 0 {
			c.WebPort = o.WebPort
		}
		if o.UPnP != nil {
			c.UPnP = *o.UPnP
		}
		c.AllowedHosts = splitHosts(o.Allowed)
	}

	str := func(name string, dst *string) {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			*dst = v
		}
	}
	num := func(name string, dst *int) error {
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 || (n == 0 && name != "WEB_PORT") {
			return fmt.Errorf("%s=%q: invalid port", name, v)
		}
		*dst = n
		return nil
	}
	str("FRIGATE_URL", &c.FrigateURL)
	str("PUBLIC_HOST", &c.PublicHost)
	for name, dst := range map[string]*int{"WG_PORT": &c.WGPort, "PUBLIC_PORT": &c.PublicPort, "WEB_PORT": &c.WebPort} {
		if err := num(name, dst); err != nil {
			return nil, err
		}
	}
	if v := strings.TrimSpace(os.Getenv("UPNP")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("UPNP=%q: true or false expected", v)
		}
		c.UPnP = b
	}
	if v := os.Getenv("ALLOWED_HOSTS"); v != "" {
		c.AllowedHosts = splitHosts(v)
	}
	if v := strings.TrimSpace(os.Getenv("CLIENT_NET")); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() || p.Bits() > 28 {
			return nil, fmt.Errorf("CLIENT_NET=%q: IPv4 subnet expected (e.g. 10.77.0.0/24)", v)
		}
		c.ClientNet = p.Masked()
	}
	if c.PublicPort == 0 {
		c.PublicPort = c.WGPort
	}
	if c.FrigateURL == "" && addon {
		lan, err := primaryLANAddr()
		if err != nil {
			return nil, fmt.Errorf("frigate_url empty and this Home Assistant's network address can't be found (%v): set frigate_url to https://<Home Assistant IP>:8971", err)
		}
		c.FrigateURL = "https://" + net.JoinHostPort(lan.String(), "8971")
		log.Printf("frigate_url empty: using the Frigate add-on on this Home Assistant, %s", c.FrigateURL)
	}
	if c.FrigateURL == "" {
		return nil, errors.New("FRIGATE_URL missing (e.g. https://192.168.1.20:8971)")
	}
	if err := c.resolveFrigate(context.Background()); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) resolveFrigate(ctx context.Context) error {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.FrigateURL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("FRIGATE_URL=%q invalid (e.g. https://192.168.1.20:8971)", c.FrigateURL)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return fmt.Errorf("FRIGATE_URL=%q: invalid port", c.FrigateURL)
	}
	c.frigate = u
	c.frigatePort = uint16(p)
	c.forwardAddr = net.JoinHostPort(u.Hostname(), port)

	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ips, lerr := net.DefaultResolver.LookupNetIP(ctx, "ip4", u.Hostname())
		if lerr != nil || len(ips) == 0 {
			return fmt.Errorf("can't resolve %q: put Frigate's IP address in FRIGATE_URL instead", u.Hostname())
		}
		ip = ips[0]
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return fmt.Errorf("FRIGATE_URL: use Frigate's IPv4 address (%s)", ip)
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		lan, err := primaryLANAddr()
		if err != nil {
			return fmt.Errorf("Frigate is on localhost but this machine's network address can't be found: put its IP in FRIGATE_URL")
		}
		ip = lan
	}
	if c.ClientNet.Contains(ip) {
		return fmt.Errorf("Frigate's address (%s) is inside CLIENT_NET (%s): choose another CLIENT_NET", ip, c.ClientNet)
	}
	c.phoneIP = ip
	c.phoneURL = fmt.Sprintf("%s://%s", u.Scheme, net.JoinHostPort(ip.String(), port))
	return nil
}

func primaryLANAddr() (netip.Addr, error) {
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, err
	}
	return ap.Addr().Unmap(), nil
}

func splitHosts(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func HealthPort() int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("WEB_PORT"))); err == nil && v > 0 {
		return v
	}
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "/data"
	}
	var o haOptions
	if b, err := os.ReadFile(filepath.Join(dir, "options.json")); err == nil && json.Unmarshal(b, &o) == nil && o.WebPort > 0 {
		return o.WebPort
	}
	return 8765
}
