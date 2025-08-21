package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

/* ==========================
   Конфиг и утилиты
   ========================== */

type Config struct {
	ServerEndpoint string   // "148.253.210.13:51820"
	ServerPubKey   string   // публичный ключ сервера (base64)
	ClientPrivKey  string   // приватный ключ клиента (base64); если пусто — сгенерим
	ClientIPv4     string   // "10.8.0.2/32"
	ClientIPv6     string   // "fd00:8::2/128" (опц.)
	DNS            []string // ["1.1.1.1","2606:4700:4700::1111"]
	MTU            int      // 1420

	Domains        []string // домены для split-tunnel
	Resolvers      []string // DNS, по умолчанию ["1.1.1.1","8.8.8.8"]
	OutputConfPath string   // путь к client.conf
}

func fail(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+msg+"\n", args...)
	os.Exit(1)
}

func mustEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func defaultConfig() *Config {
	return &Config{
		ServerEndpoint: mustEnv("WG_SERVER_ENDPOINT", "148.253.210.13:51820"),
		ServerPubKey:   mustEnv("WG_SERVER_PUB", ""),
		ClientPrivKey:  mustEnv("WG_CLIENT_PRIV", ""),
		ClientIPv4:     mustEnv("WG_CLIENT_IPV4", "10.8.0.2/32"),
		ClientIPv6:     os.Getenv("WG_CLIENT_IPV6"),
		DNS:            []string{"1.1.1.1", "2606:4700:4700::1111"},
		MTU:            1420,
		Resolvers:      []string{"1.1.1.1", "8.8.8.8"},
		// ЖЁСТКО заданный список доменов на старте:
		Domains:        []string{"chatgpt.com", "youtube.com", "www.youtube.com", "api.ipify.org"},
		OutputConfPath: "client.conf",
	}
}

// WireGuard private key — base64(32 байта). Для PoC просто сгенерим 32 случайных байта,
// но в реале лучше передать настоящий ключ клиента через --priv.
func genBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

/* ==========================
   main
   ========================== */

func main() {
	conf := defaultConfig()

	// флаги
	var (
		flagOnce      bool
		flagWatch     time.Duration
		flagDomains   string
		flagResolvers string
		flagOutConf   string
		flagDNS       string
		flagMTU       int
		flagIPv6      string
		flagSrvEP     string
		flagSrvPub    string
		flagCliPriv   string
		flagCliIPv4   string
	)
	flag.BoolVar(&flagOnce, "once", false, "Сделать один проход и выйти")
	flag.DurationVar(&flagWatch, "watch", 0, "Период обновления, напр. 30m, 1h")
	flag.StringVar(&flagDomains, "domains", strings.Join(conf.Domains, ","), "Домены через запятую")
	flag.StringVar(&flagResolvers, "resolvers", strings.Join(conf.Resolvers, ","), "DNS-резолверы через запятую")
	flag.StringVar(&flagOutConf, "out", conf.OutputConfPath, "Путь к client.conf")
	flag.StringVar(&flagDNS, "dns", strings.Join(conf.DNS, ","), "DNS для клиента (через запятую)")
	flag.IntVar(&flagMTU, "mtu", conf.MTU, "MTU для клиента")
	flag.StringVar(&flagIPv6, "ipv6", conf.ClientIPv6, "IPv6 клиента (например fd00:8::2/128); пусто — не писать")
	flag.StringVar(&flagSrvEP, "endpoint", conf.ServerEndpoint, "Endpoint сервера host:port")
	flag.StringVar(&flagSrvPub, "pub", conf.ServerPubKey, "PublicKey сервера (base64)")
	flag.StringVar(&flagCliPriv, "priv", conf.ClientPrivKey, "PrivateKey клиента (base64); пусто — сгенерим")
	flag.StringVar(&flagCliIPv4, "ipv4", conf.ClientIPv4, "IPv4 клиента, напр. 10.8.0.2/32")
	flag.Parse()

	// применяем флаги
	conf.Domains = splitCSV(flagDomains)
	conf.Resolvers = splitCSV(flagResolvers)
	conf.OutputConfPath = flagOutConf
	conf.DNS = splitCSV(flagDNS)
	conf.MTU = flagMTU
	conf.ClientIPv6 = flagIPv6
	conf.ServerEndpoint = flagSrvEP
	conf.ServerPubKey = flagSrvPub
	conf.ClientPrivKey = flagCliPriv
	conf.ClientIPv4 = flagCliIPv4

	if conf.ServerPubKey == "" {
		fail("не задан --pub (публичный ключ сервера)")
	}
	if conf.ClientPrivKey == "" {
		k, err := genBase64(32)
		if err != nil {
			fail("не удалось сгенерировать приватный ключ: %v", err)
		}
		conf.ClientPrivKey = k
	}

	run := func() {
		if err := doOnce(conf); err != nil {
			fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		} else {
			fmt.Println("[OK] client.conf обновлён")
		}
	}

	if flagOnce || flagWatch == 0 {
		run()
		return
	}

	// watch-режим
	t := time.NewTicker(flagWatch)
	defer t.Stop()
	run()
	for range t.C {
		run()
	}
}

/* ==========================
   Логика
   ========================== */

func doOnce(c *Config) error {
	if len(c.Domains) == 0 {
		return errors.New("пустой список доменов")
	}
	ips, err := resolveDomainsMulti(c.Domains, c.Resolvers)
	if err != nil {
		return err
	}
	allowed := toCIDRs(ips)

	// собрать client.conf
	body := buildClientConf(c, allowed)

	// создать каталог, если надо
	if err := os.MkdirAll(filepath.Dir(c.OutputConfPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(c.OutputConfPath, []byte(body), 0o600); err != nil {
		return err
	}
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveDomainsMulti(domains, resolvers []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		for _, r := range resolvers {
			v4, v6 := resolverFor(r)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			addrs4, _ := v4.LookupHost(ctx, d)
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
			addrs6, _ := v6.LookupHost(ctx, d)
			cancel()

			for _, a := range append(addrs4, addrs6...) {
				if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
					set[ip.String()] = struct{}{}
				}
			}
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("не удалось получить IP для: %v", strings.Join(domains, ", "))
	}
	ips := make([]string, 0, len(set))
	for k := range set {
		ips = append(ips, k)
	}
	sort.Strings(ips)
	return ips, nil
}

func resolverFor(r string) (*net.Resolver, *net.Resolver) {
	// Резолвим напрямую в r:53 (UDP)
	dialer := func(network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.Dial("udp", net.JoinHostPort(r, "53"))
	}
	makeRes := func() *net.Resolver {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer(network, address)
			},
		}
	}
	return makeRes(), makeRes()
}

func toCIDRs(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			out = append(out, ip.String()+"/32")
		} else {
			out = append(out, ip.String()+"/128")
		}
	}
	return out
}

func buildClientConf(c *Config, allowed []string) string {
	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.ClientPrivKey)
	fmt.Fprintf(&b, "Address = %s", c.ClientIPv4)
	if strings.TrimSpace(c.ClientIPv6) != "" {
		fmt.Fprintf(&b, ", %s", c.ClientIPv6)
	}
	fmt.Fprintln(&b)
	if len(c.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(c.DNS, ", "))
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "[Peer]")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPubKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", c.ServerEndpoint)
	fmt.Fprintln(&b, "PersistentKeepalive = 25")
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	return b.String()
}
