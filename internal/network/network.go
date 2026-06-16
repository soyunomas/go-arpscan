// internal/network/network.go
package network

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ResolveTargets toma una lista de strings y los convierte en una lista única de IPs.
// Soporta: IPs individuales, rangos de IP (1.1.1.1-1.1.1.10), CIDRs,
// formato red:máscara (192.168.1.0:255.255.255.0, compatible con arp-scan)
// y hostnames (a menos que numeric sea true).
func ResolveTargets(targets []string, numeric bool, excludeBroadcast bool) ([]net.IP, error) {
	ipMap := make(map[string]struct{})

	for _, target := range targets {
		// Intento 0: ¿Es notación red:máscara estilo arp-scan? (e.g., 192.168.1.0:255.255.255.0)
		if idx := strings.Index(target, ":"); idx > 0 && strings.Count(target, ":") == 1 {
			netStr, maskStr := target[:idx], target[idx+1:]
			netIP := net.ParseIP(netStr)
			maskIP := net.ParseIP(maskStr)
			if netIP != nil && maskIP != nil && netIP.To4() != nil && maskIP.To4() != nil {
				mask := net.IPv4Mask(maskIP.To4()[0], maskIP.To4()[1], maskIP.To4()[2], maskIP.To4()[3])
				ipNet := &net.IPNet{IP: netIP.Mask(mask), Mask: mask}
				ips, err := GetIPs(ipNet, excludeBroadcast)
				if err != nil {
					return nil, fmt.Errorf("error generating IPs for %s: %w", target, err)
				}
				for _, ip := range ips {
					ipMap[ip.String()] = struct{}{}
				}
				continue
			}
		}

		// Intento 1: ¿Es un rango de IP? (e.g., 192.168.1.10-192.168.1.20)
		if strings.Contains(target, "-") {
			parts := strings.Split(target, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("malformed IP range: %s", target)
			}
			startIP := net.ParseIP(parts[0])
			endIP := net.ParseIP(parts[1])
			if startIP == nil || endIP == nil {
				return nil, fmt.Errorf("invalid IP in range: %s", target)
			}

			if bytes.Compare(startIP, endIP) > 0 {
				return nil, fmt.Errorf("range start IP is greater than end IP: %s", target)
			}

			for ip := startIP; bytes.Compare(ip, endIP) <= 0; inc(ip) {
				ipCopy := make(net.IP, len(ip))
				copy(ipCopy, ip)
				ipMap[ipCopy.String()] = struct{}{}
			}
			continue
		}

		// Intento 2: ¿Es una notación CIDR? (e.g., 192.168.1.0/24)
		_, ipNet, err := net.ParseCIDR(target)
		if err == nil {
			ips, err := GetIPs(ipNet, excludeBroadcast)
			if err != nil {
				return nil, fmt.Errorf("error generating IPs for CIDR %s: %w", target, err)
			}
			for _, ip := range ips {
				ipMap[ip.String()] = struct{}{}
			}
			continue
		}

		// Intento 3: ¿Es una IP individual? (e.g., 192.168.1.1)
		ip := net.ParseIP(target)
		if ip != nil {
			ipMap[ip.String()] = struct{}{}
			continue
		}

		// Intento 4 (último recurso): ¿Es un hostname? (Solo si --numeric no está activo)
		if !numeric {
			resolvedIPs, err := net.LookupIP(target)
			if err == nil {
				foundIPv4 := false
				for _, resolvedIP := range resolvedIPs {
					// Solo nos interesan las direcciones IPv4 para ARP
					if resolvedIP.To4() != nil {
						ipMap[resolvedIP.String()] = struct{}{}
						foundIPv4 = true
					}
				}
				if foundIPv4 {
					continue
				}
			}
		}

		// Si llegamos aquí, no pudimos interpretar el target
		return nil, fmt.Errorf("unrecognized target format or could not resolve: %s", target)
	}

	var result []net.IP
	for ipStr := range ipMap {
		result = append(result, net.ParseIP(ipStr))
	}
	return result, nil
}

func GetIPs(cidr *net.IPNet, excludeBroadcast bool) ([]net.IP, error) {
	var ips []net.IP
	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
		dstIP := make(net.IP, len(ip))
		copy(dstIP, ip)
		ips = append(ips, dstIP)
	}
	if excludeBroadcast && len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func GetInterfaceByName(name string) (*net.Interface, *net.IPNet, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("could not find interface %q: %w", name, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("could not get addresses for interface %q: %w", name, err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return iface, ipnet, nil
		}
	}
	return nil, nil, errors.New("no valid IPv4 address found on interface")
}

// GetDefaultInterface intenta encontrar la mejor interfaz de red para usar por defecto.
func GetDefaultInterface() (*net.Interface, *net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("could not list network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Criterios para una buena interfaz por defecto:
		// 1. Está activa (Up).
		// 2. No es una interfaz de loopback.
		// 3. Soporta multicast (un buen indicador de que es una interfaz "real").
		// 4. Tiene al menos una dirección IPv4.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue // No podemos obtener direcciones, la saltamos.
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				// Encontramos una interfaz adecuada. La devolvemos.
				return &iface, ipnet, nil
			}
		}
	}

	return nil, nil, errors.New("could not find an active valid network interface with an IPv4 address")
}
