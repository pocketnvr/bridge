package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ssdpAddr = "239.255.255.250:1900"

var upnpClient = &http.Client{
	Timeout:       6 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func fromLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

var igdServices = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

type igd struct {
	controlURL  string
	serviceType string
	localIP     string
	name        string
}

func discoverIGD(ctx context.Context) (*igd, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}
	for _, st := range append([]string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, igdServices...) {
		msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n"
		if _, err := pc.WriteTo([]byte(msg), dst); err != nil {
			return nil, err
		}
	}
	dl, _ := ctx.Deadline()
	_ = pc.SetReadDeadline(dl)

	seen := map[string]bool{}
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return nil, errNoIGD
		}
		src, err := netip.ParseAddrPort(from.String())
		if err != nil || !fromLAN(src.Addr()) {
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" || seen[loc] {
			continue
		}
		seen[loc] = true
		u, err := url.Parse(loc)
		if err != nil || u.Scheme != "http" {
			continue
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err != nil || ip.Unmap() != src.Addr().Unmap() {
			continue
		}
		if g, err := loadIGD(ctx, loc); err == nil {
			return g, nil
		}
	}
}

type upnpDevice struct {
	FriendlyName string        `xml:"friendlyName"`
	ModelName    string        `xml:"modelName"`
	Services     []upnpService `xml:"serviceList>service"`
	Devices      []upnpDevice  `xml:"deviceList>device"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func loadIGD(ctx context.Context, location string) (*igd, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	resp, err := upnpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UPnP description: HTTP %d", resp.StatusCode)
	}
	var root struct {
		URLBase string     `xml:"URLBase"`
		Device  upnpDevice `xml:"device"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&root); err != nil {
		return nil, err
	}
	base, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	if root.URLBase != "" {
		if b, err := url.Parse(root.URLBase); err == nil && b.Hostname() == base.Hostname() {
			base = b
		}
	}

	var find func(d upnpDevice) *upnpService
	find = func(d upnpDevice) *upnpService {
		for _, want := range igdServices {
			for i := range d.Services {
				if d.Services[i].ServiceType == want {
					return &d.Services[i]
				}
			}
		}
		for _, sub := range d.Devices {
			if s := find(sub); s != nil {
				return s
			}
		}
		return nil
	}
	svc := find(root.Device)
	if svc == nil {
		return nil, errors.New("no WAN service")
	}
	ctrl, err := base.Parse(svc.ControlURL)
	if err != nil {
		return nil, err
	}
	if ctrl.Scheme != "http" || ctrl.Hostname() != base.Hostname() {
		return nil, errors.New("UPnP control URL outside the router")
	}

	c, err := net.Dial("udp4", ctrl.Host)
	if err != nil {
		if c, err = net.Dial("udp4", net.JoinHostPort(ctrl.Hostname(), "80")); err != nil {
			return nil, err
		}
	}
	local := c.LocalAddr().(*net.UDPAddr).IP.String()
	c.Close()

	name := root.Device.FriendlyName
	if name == "" {
		name = root.Device.ModelName
	}
	return &igd{controlURL: ctrl.String(), serviceType: svc.ServiceType, localIP: local, name: name}, nil
}

type soapFault struct {
	Code        int
	Description string
}

func (f *soapFault) Error() string {
	return fmt.Sprintf("UPnP %d %s", f.Code, f.Description)
}

func (g *igd) call(ctx context.Context, action string, args [][2]string) (map[string]string, error) {
	var body strings.Builder
	body.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&body, `<u:%s xmlns:u="%s">`, action, g.serviceType)
	for _, a := range args {
		body.WriteString("<" + a[0] + ">")
		_ = xml.EscapeText(&body, []byte(a[1]))
		body.WriteString("</" + a[0] + ">")
	}
	fmt.Fprintf(&body, `</u:%s></s:Body></s:Envelope>`, action)

	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL, strings.NewReader(body.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, g.serviceType, action))
	resp, err := upnpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var stack []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				if v := strings.TrimSpace(string(t)); v != "" {
					out[stack[len(stack)-1]] = v
				}
			}
		}
	}
	if resp.StatusCode != http.StatusOK {
		f := &soapFault{Description: out["errorDescription"]}
		fmt.Sscanf(out["errorCode"], "%d", &f.Code)
		if f.Code == 0 {
			return nil, fmt.Errorf("UPnP %s: HTTP %d", action, resp.StatusCode)
		}
		return nil, f
	}
	return out, nil
}

func (g *igd) externalIP(ctx context.Context) (netip.Addr, error) {
	out, err := g.call(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(out["NewExternalIPAddress"])
}

func (g *igd) addUDPMapping(ctx context.Context, external, internal int, lease int) error {
	_, err := g.call(ctx, "AddPortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", fmt.Sprint(external)},
		{"NewProtocol", "UDP"},
		{"NewInternalPort", fmt.Sprint(internal)},
		{"NewInternalClient", g.localIP},
		{"NewEnabled", "1"},
		{"NewPortMappingDescription", "PocketNVR Bridge"},
		{"NewLeaseDuration", fmt.Sprint(lease)},
	})
	return err
}

func (g *igd) deleteUDPMapping(ctx context.Context, external int) error {
	_, err := g.call(ctx, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", fmt.Sprint(external)},
		{"NewProtocol", "UDP"},
	})
	return err
}

const (
	upnpNoRouter = "no_router"
	upnpConflict = "conflict"
	upnpRefused  = "refused"
)

var errNoIGD = errors.New("no UPnP router answered (UPnP disabled on the router?)")

type UPnPStatus struct {
	Enabled    bool
	OK         bool
	Router     string
	ExternalIP netip.Addr
	Code       string
	Error      string
	Checked    time.Time
}

type PortKeeper struct {
	external, internal int

	mu     sync.Mutex
	status UPnPStatus
	gw     *igd
	lease  int
}

const upnpLease = 3600

func newPortKeeper(external, internal int) *PortKeeper {
	return &PortKeeper{external: external, internal: internal, lease: upnpLease, status: UPnPStatus{Enabled: true}}
}

func (k *PortKeeper) Status() UPnPStatus {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.status
}

func (k *PortKeeper) Run(ctx context.Context) {
	for {
		k.refresh(ctx)
		wait := 20 * time.Minute
		if !k.Status().OK {
			wait = 2 * time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (k *PortKeeper) refresh(ctx context.Context) {
	k.mu.Lock()
	gw, lease := k.gw, k.lease
	k.mu.Unlock()

	st := UPnPStatus{Enabled: true, Checked: time.Now()}
	if gw == nil {
		var err error
		if gw, err = discoverIGD(ctx); err != nil {
			st.Error = err.Error()
			if errors.Is(err, errNoIGD) {
				st.Code = upnpNoRouter
			}
			k.set(st, nil)
			return
		}
		log.Printf("UPnP: router found (%s)", gw.name)
	}
	st.Router = gw.name

	err := gw.addUDPMapping(ctx, k.external, k.internal, lease)
	var fault *soapFault
	if errors.As(err, &fault) && fault.Code == 725 {
		lease = 0
		err = gw.addUDPMapping(ctx, k.external, k.internal, 0)
	}
	if err != nil {
		st.Code, st.Error = upnpRefused, "router refused the UDP port mapping: "+err.Error()
		if errors.As(err, &fault) && fault.Code == 718 {
			st.Code, st.Error = upnpConflict, fmt.Sprintf("UDP port %d is already mapped to another device", k.external)
		}
		k.set(st, nil)
		return
	}
	if ip, err := gw.externalIP(ctx); err == nil {
		st.ExternalIP = ip
	}
	st.OK = true
	k.mu.Lock()
	k.lease = lease
	k.mu.Unlock()
	k.set(st, gw)
}

func (k *PortKeeper) set(st UPnPStatus, gw *igd) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !st.OK && k.status.OK {
		log.Printf("UPnP: %s", st.Error)
	}
	if st.OK && !k.status.OK {
		log.Printf("UPnP: UDP port %d open on the router (%s)", k.external, st.Router)
	}
	k.status = st
	k.gw = gw
}

func (k *PortKeeper) Close() {
	k.mu.Lock()
	gw := k.gw
	k.mu.Unlock()
	if gw != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = gw.deleteUDPMapping(ctx, k.external)
	}
}
