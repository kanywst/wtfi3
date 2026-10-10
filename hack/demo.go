//go:build ignore

// demo serves the dashboard with synthetic, ever-changing household traffic so
// the UI can be developed and screenshotted without root, a live network, or a
// pcap. It reads internal/web/index.html from disk on every request, so edits
// show up on reload.
//
//	go run hack/demo.go            # http://localhost:8099
//	go run hack/demo.go -listen :9000
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type device struct {
	IP, MAC, Vendor string
	Tx, Rx          uint64
	joinAt          int // tick at which the device appears
	plan            [][]string
}

type flow struct {
	Src, Dst, Proto, SNI string
	Port                 int
	Bytes, Packets       uint64
}

type dnsEntry struct {
	Client, Name, Type, Answer string
	Time                       time.Time
}

var (
	mu     sync.Mutex
	tick   int
	start  = time.Now()
	series []float64
	flows  = map[string]*flow{}
	dns    []dnsEntry
	devs   = []*device{
		{IP: "192.168.1.1", MAC: "f4:92:bf:00:00:01", Vendor: "Ubiquiti Inc"},
		{IP: "192.168.1.10", MAC: "a4:83:e7:10:20:30", Vendor: "Apple, Inc.", plan: [][]string{
			{"github.com", "api.anthropic.com"}, {"www.youtube.com", "rr3---sn-a5m.googlevideo.com"}, {"slack.com", "edgeapi.slack.com"}}},
		{IP: "192.168.1.21", MAC: "5a:11:22:33:44:55", Vendor: "randomized?", plan: [][]string{
			{"www.instagram.com", "scontent.cdninstagram.com", "graph.facebook.com", "app-measurement.com"},
			{"open.spotify.com", "audio-ak.scdn.co"}, {"api.line.me", "app-measurement.com"}}},
		{IP: "192.168.1.31", MAC: "8c:79:f5:aa:bb:cc", Vendor: "Samsung Electronics Co.,Ltd", plan: [][]string{
			{"ipv4-c001.nflxvideo.net", "api.netflix.com", "samsungacr.com"}, {"www.youtube.com", "rr1---sn-a5m.googlevideo.com", "samsungads.com"}}},
		{IP: "192.168.1.42", MAC: "24:0a:c4:12:34:56", Vendor: "Espressif Inc.", plan: [][]string{
			{"a1.tuyaus.com", "m1.tuyaus.com"}}},
		{IP: "192.168.1.43", MAC: "fc:65:de:01:02:03", Vendor: "Amazon Technologies Inc.", plan: [][]string{
			{"music.amazon.com", "device-metrics-us.amazon.com"}, {"avs-alexa-na.amazon.com"}}},
		{IP: "192.168.1.55", MAC: "98:b6:e9:aa:00:11", Vendor: "Nintendo Co.,Ltd", plan: [][]string{
			{"atum.hac.lp1.d4c.nintendo.net", "accounts.nintendo.com"}}},
		{IP: "192.168.1.60", MAC: "3c:22:fb:99:88:77", Vendor: "Apple, Inc.", plan: [][]string{
			{"www.amazon.co.jp", "m.media-amazon.com", "googleads.g.doubleclick.net", "www.google-analytics.com", "static.criteo.net"},
			{"www.netflix.com", "ipv4-c002.nflxvideo.net"}}},
		{IP: "192.168.1.77", MAC: "7c:a7:b0:de:ad:01", Vendor: "Shenzhen Reolink Technology", joinAt: 40, plan: [][]string{
			{"p2p.reolink.com", "a2.tuyaeu.com"}}},
	}
)

func step() {
	mu.Lock()
	defer mu.Unlock()
	tick++
	var total uint64
	for i, d := range devs {
		if tick < d.joinAt || d.plan == nil {
			if tick >= d.joinAt && i == 0 {
				d.Rx += 200
			}
			continue
		}
		phase := d.plan[(tick/25+i)%len(d.plan)]
		// Idle now and then, so the timeline and the live map breathe.
		if rand.IntN(10) < 2 {
			continue
		}
		for j, host := range phase {
			heavy := j == 0 && d.Vendor != "Espressif Inc." && rand.IntN(3) > 0
			n := uint64(800 + rand.IntN(20000))
			if heavy {
				n = uint64(200000 + rand.IntN(900000))
			}
			if j > 0 && rand.IntN(3) == 0 {
				continue
			}
			k := d.IP + ">" + host
			f := flows[k]
			if f == nil {
				f = &flow{Src: d.IP, Dst: fmt.Sprintf("203.0.113.%d", 1+len(flows)%250), Proto: "tcp", Port: 443, SNI: host}
				flows[k] = f
				dns = append(dns, dnsEntry{Client: d.IP, Name: host, Type: "A", Answer: f.Dst, Time: time.Now()})
				if len(dns) > 80 {
					dns = dns[len(dns)-80:]
				}
			}
			f.Bytes += n
			f.Packets += n/1200 + 1
			d.Rx += n * 9 / 10
			d.Tx += n / 10
			total += n
		}
	}
	series = append(series, float64(total))
	if len(series) > 120 {
		series = series[len(series)-120:]
	}
}

func snapshot() map[string]any {
	mu.Lock()
	defer mu.Unlock()
	var dl []map[string]any
	var tot uint64
	for _, d := range devs {
		if tick < d.joinAt {
			continue
		}
		tot += d.Tx + d.Rx
		dl = append(dl, map[string]any{"ip": d.IP, "mac": d.MAC, "vendor": d.Vendor,
			"tx_bytes": d.Tx, "rx_bytes": d.Rx, "new": d.joinAt > 0 && tick-d.joinAt < 90})
	}
	var fl []*flow
	for _, f := range flows {
		fl = append(fl, f)
	}
	sort.Slice(fl, func(a, b int) bool { return fl[a].Bytes > fl[b].Bytes })
	if len(fl) > 50 {
		fl = fl[:50]
	}
	var fo []map[string]any
	for _, f := range fl {
		fo = append(fo, map[string]any{"src": f.Src, "dst": f.Dst, "proto": f.Proto, "dst_port": f.Port,
			"sni": f.SNI, "bytes": f.Bytes, "packets": f.Packets})
	}
	var do []map[string]any
	for i := len(dns) - 1; i >= 0; i-- {
		e := dns[i]
		do = append(do, map[string]any{"client": e.Client, "name": e.Name, "type": e.Type, "answer": e.Answer})
	}
	return map[string]any{
		"iface": "en0", "self_ip": "192.168.1.10", "gateway": "192.168.1.1", "version": "demo",
		"wifi":  map[string]any{"connected": true, "ssid": "home-net", "bssid": "f4:92:bf:00:00:02", "security": "WPA2_PSK"},
		"spoof": true, "spoof_list": []string{"192.168.1.21", "192.168.1.31", "192.168.1.42"},
		"uptime_sec": time.Since(start).Seconds(), "total_mb": float64(tot) / 1e6,
		"devices": dl, "flows": fo, "dns": do, "series": series,
	}
}

func main() {
	listen := flag.String("listen", ":8099", "listen address")
	flag.Parse()
	go func() {
		for range time.Tick(time.Second) {
			step()
		}
	}()
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile("internal/web/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	http.HandleFunc("/api/state", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(snapshot())
	})
	http.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			b, _ := json.Marshal(snapshot())
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-t.C:
			}
		}
	})
	log.Printf("demo dashboard on http://localhost%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
