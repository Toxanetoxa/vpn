package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Server settings
	ServerIP         string
	ServerPort       int
	ServerNetwork    string
	ServerPrivKey    string
	ServerPubKey     string
	ServerConfigPath string

	// Client settings
	ClientIP         string
	ClientPrivKey    string
	ClientPubKey     string
	ClientConfigPath string

	// Common settings
	DNS           []string
	MTU           int
	Domains       []string
	Resolvers     []string
	InterfaceName string
}

func main() {
	config := &Config{
		ServerIP:         "10.8.0.1",
		ServerPort:       51820,
		ServerNetwork:    "10.8.0.0/24",
		ServerConfigPath: "/etc/wireguard/wg0.conf",
		ClientIP:         "10.8.0.2",
		ClientConfigPath: "wg-client.conf",
		DNS:              []string{"1.1.1.1", "8.8.8.8"},
		MTU:              1420,
		Domains:          []string{"youtube.com", "chatgpt.com", "netflix.com"},
		Resolvers:        []string{"1.1.1.1", "8.8.8.8"},
		InterfaceName:    "wg0",
	}

	// Parse flags
	mode := flag.String("mode", "client", "Mode: server|client|both")
	flag.Parse()

	// Generate keys if not exists
	if config.ServerPrivKey == "" {
		priv, pub, err := generateKeyPair()
		if err != nil {
			fail("Failed to generate keys: %v", err)
		}
		config.ServerPrivKey = priv
		config.ServerPubKey = pub
	}

	if config.ClientPrivKey == "" {
		priv, pub, err := generateKeyPair()
		if err != nil {
			fail("Failed to generate client keys: %v", err)
		}
		config.ClientPrivKey = priv
		config.ClientPubKey = pub
	}

	switch *mode {
	case "server":
		if err := setupServer(config); err != nil {
			fail("Server setup failed: %v", err)
		}
	case "client":
		if err := setupClient(config); err != nil {
			fail("Client setup failed: %v", err)
		}
	case "both":
		if err := setupServer(config); err != nil {
			fail("Server setup failed: %v", err)
		}
		if err := setupClient(config); err != nil {
			fail("Client setup failed: %v", err)
		}
	default:
		fail("Invalid mode. Use: server|client|both")
	}
}

func setupServer(config *Config) error {
	fmt.Println("Setting up WireGuard server...")

	// Resolve domains
	allowedIPs, err := resolveDomains(config.Domains, config.Resolvers)
	if err != nil {
		return fmt.Errorf("failed to resolve domains: %v", err)
	}

	// Create server config
	serverConfig := buildServerConfig(config, allowedIPs)

	// Write config
	if err := os.MkdirAll(filepath.Dir(config.ServerConfigPath), 0755); err != nil {
		return err
	}

	if err := ioutil.WriteFile(config.ServerConfigPath, []byte(serverConfig), 0600); err != nil {
		return err
	}

	// Setup firewall and NAT
	if err := setupFirewall(config); err != nil {
		return fmt.Errorf("firewall setup failed: %v", err)
	}

	// Enable IP forwarding
	if err := enableIPForwarding(); err != nil {
		return fmt.Errorf("IP forwarding setup failed: %v", err)
	}

	fmt.Printf("Server config created: %s\n", config.ServerConfigPath)
	fmt.Printf("Server public key: %s\n", config.ServerPubKey)

	return startWireGuard(config.InterfaceName)
}

func setupClient(config *Config) error {
	fmt.Println("Setting up WireGuard client...")

	// Resolve domains
	allowedIPs, err := resolveDomains(config.Domains, config.Resolvers)
	if err != nil {
		return fmt.Errorf("failed to resolve domains: %v", err)
	}

	// Create client config
	clientConfig := buildClientConfig(config, allowedIPs)

	// Write config
	if err := ioutil.WriteFile(config.ClientConfigPath, []byte(clientConfig), 0600); err != nil {
		return err
	}

	fmt.Printf("Client config created: %s\n", config.ClientConfigPath)
	fmt.Printf("Client public key: %s\n", config.ClientPubKey)

	return nil
}

func buildServerConfig(config *Config, allowedIPs []string) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("Address = %s/24\n", config.ServerIP))
	b.WriteString(fmt.Sprintf("ListenPort = %d\n", config.ServerPort))
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.ServerPrivKey))
	b.WriteString(fmt.Sprintf("MTU = %d\n", config.MTU))
	b.WriteString("\n")

	// NAT and firewall rules
	b.WriteString("PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n")
	b.WriteString("PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n")
	b.WriteString("\n")

	// Client peer
	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", config.ClientPubKey))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s/32\n", config.ClientIP))
	if len(allowedIPs) > 0 {
		b.WriteString(fmt.Sprintf("# Allowed domains: %s\n", strings.Join(config.Domains, ", ")))
	}

	return b.String()
}

func buildClientConfig(config *Config, allowedIPs []string) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.ClientPrivKey))
	b.WriteString(fmt.Sprintf("Address = %s/24\n", config.ClientIP))
	b.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(config.DNS, ", ")))
	b.WriteString(fmt.Sprintf("MTU = %d\n", config.MTU))
	b.WriteString("\n")

	b.WriteString("[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", config.ServerPubKey))
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", getPublicIP(), config.ServerPort))
	b.WriteString("PersistentKeepalive = 25\n")

	if len(allowedIPs) > 0 {
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowedIPs, ", ")))
	} else {
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	}

	return b.String()
}

func generateKeyPair() (string, string, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}

	// In real implementation, use proper WireGuard key generation
	privBase64 := base64.StdEncoding.EncodeToString(privateKey)
	pubBase64 := base64.StdEncoding.EncodeToString(derivePublicKey(privateKey))

	return privBase64, pubBase64, nil
}

func derivePublicKey(privateKey []byte) []byte {
	// Simplified - in real implementation use proper crypto
	return privateKey
}

func resolveDomains(domains, resolvers []string) ([]string, error) {
	ips := make(map[string]bool)

	for _, domain := range domains {
		addrs, err := net.LookupIP(domain)
		if err != nil {
			fmt.Printf("Warning: failed to resolve %s: %v\n", domain, err)
			continue
		}

		for _, addr := range addrs {
			if addr.To4() != nil {
				ips[addr.String()+"/32"] = true
			} else {
				ips[addr.String()+"/128"] = true
			}
		}
	}

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}
	sort.Strings(result)

	return result, nil
}

func setupFirewall(config *Config) error {
	commands := []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -A FORWARD -i wg0 -j ACCEPT",
		"iptables -A FORWARD -o wg0 -j ACCEPT",
		"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
		"ufw allow 51820/udp",
	}

	for _, cmd := range commands {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			fmt.Printf("Warning: failed to run %s: %v\n", cmd, err)
		}
	}

	return nil
}

func enableIPForwarding() error {
	return ioutil.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

func startWireGuard(interfaceName string) error {
	// Stop if already running
	exec.Command("wg-quick", "down", interfaceName).Run()

	// Start new interface
	return exec.Command("wg-quick", "up", interfaceName).Run()
}

func getPublicIP() string {
	// You should replace this with your server's actual public IP
	return "YOUR_SERVER_PUBLIC_IP"
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
