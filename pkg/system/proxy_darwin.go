//go:build darwin
// +build darwin

package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// getNetworkServices returns a list of all network services
func getNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list network services: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var services []string
	
	// Skip the first line which contains a notice about asterisks
	for i := 1; i < len(lines); i++ {
		service := strings.TrimSpace(lines[i])
		if service != "" && !strings.HasPrefix(service, "*") {
			services = append(services, service)
		}
	}
	
	return services, nil
}

// selectNetworkService prompts the user to select a network service
func selectNetworkService() (string, error) {
	services, err := getNetworkServices()
	if err != nil {
		return "", err
	}
	
	if len(services) == 0 {
		return "", fmt.Errorf("no network services found")
	}
	
	fmt.Println("\nAvailable network services:")
	for i, service := range services {
		fmt.Printf("%d. %s\n", i+1, service)
	}
	
	fmt.Print("\nSelect a network service (enter number): ")
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read user input: %w", err)
	}
	
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil {
		return "", fmt.Errorf("invalid input: please enter a number")
	}
	
	if choice < 1 || choice > len(services) {
		return "", fmt.Errorf("invalid choice: please select a number between 1 and %d", len(services))
	}
	
	return services[choice-1], nil
}

// EnableSystemProxy enables the macOS system proxy settings
func EnableSystemProxy(proxyServer string) error {
	service, err := selectNetworkService()
	if err != nil {
		return err
	}
	
	// Parse proxy server address
	parts := strings.Split(proxyServer, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid proxy server format, expected host:port")
	}
	
	host := parts[0]
	port := parts[1]
	
	fmt.Printf("\nConfiguring proxy for service: %s\n", service)
	fmt.Println("\nNote: Administrator privileges are required to modify network settings.")
	fmt.Println("You may be prompted for your password.")
	
	// Configure and enable HTTP proxy
	cmd := exec.Command("sudo", "networksetup", "-setwebproxy", service, host, port, "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set HTTP proxy: %w\nOutput: %s", err, output)
	}
	
	cmd = exec.Command("sudo", "networksetup", "-setwebproxystate", service, "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable HTTP proxy: %w\nOutput: %s", err, output)
	}
	
	// Configure and enable HTTPS proxy
	cmd = exec.Command("sudo", "networksetup", "-setsecurewebproxy", service, host, port, "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set HTTPS proxy: %w\nOutput: %s", err, output)
	}
	
	cmd = exec.Command("sudo", "networksetup", "-setsecurewebproxystate", service, "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable HTTPS proxy: %w\nOutput: %s", err, output)
	}
	
	fmt.Println("Proxy enabled successfully")
	return nil
}

// DisableSystemProxy disables the macOS system proxy settings
func DisableSystemProxy() error {
	service, err := selectNetworkService()
	if err != nil {
		return err
	}
	
	fmt.Printf("\nDisabling proxy for service: %s\n", service)
	fmt.Println("\nNote: Administrator privileges are required to modify network settings.")
	fmt.Println("You may be prompted for your password.")
	
	// Disable HTTP proxy
	cmd := exec.Command("sudo", "networksetup", "-setwebproxystate", service, "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable HTTP proxy: %w\nOutput: %s", err, output)
	}
	
	// Disable HTTPS proxy
	cmd = exec.Command("sudo", "networksetup", "-setsecurewebproxystate", service, "off")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to disable HTTPS proxy: %w\nOutput: %s", err, output)
	}
	
	fmt.Println("Proxy disabled successfully")
	return nil
}

// GetSystemProxyStatus returns the current proxy status and server
func GetSystemProxyStatus() (enabled bool, proxyServer string, err error) {
	service, err := selectNetworkService()
	if err != nil {
		return false, "", err
	}
	
	// Check HTTP proxy status
	cmd := exec.Command("networksetup", "-getwebproxy", service)
	output, err := cmd.Output()
	if err != nil {
		return false, "", fmt.Errorf("failed to get proxy status: %w", err)
	}
	
	// Parse the output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Enabled:") {
			if strings.Contains(line, "Yes") {
				enabled = true
			}
		}
		if strings.HasPrefix(line, "Server:") && enabled {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				server := parts[1]
				// Find port
				for _, l := range lines {
					if strings.HasPrefix(l, "Port:") {
						portParts := strings.Fields(l)
						if len(portParts) >= 2 {
							proxyServer = fmt.Sprintf("%s:%s", server, portParts[1])
							break
						}
					}
				}
			}
		}
	}
	
	return enabled, proxyServer, nil
}