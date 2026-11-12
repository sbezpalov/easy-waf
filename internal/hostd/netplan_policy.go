// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v4"
)

var netplanAllowedNetworkKeys = map[string]bool{
	"version":       true,
	"renderer":      true,
	"ethernets":     true,
	"wifis":         true,
	"bridges":       true,
	"bonds":         true,
	"vlans":         true,
	"dummy-devices": true,
}

var netplanInterfaceKeys = map[string]bool{
	"ethernets":     true,
	"wifis":         true,
	"bridges":       true,
	"bonds":         true,
	"vlans":         true,
	"dummy-devices": true,
}

var netplanForbiddenKeys = map[string]bool{
	"tunnels":     true,
	"wireguard":   true,
	"openvswitch": true,
	"modems":      true,
	"nm-devices":  true,
	"vrfs":        true,
}

var netplanForbiddenTypes = map[string]bool{
	"wireguard": true,
	"tunnel":    true,
	"vxlan":     true,
	"gre":       true,
	"ipip":      true,
	"sit":       true,
	"vti":       true,
}

// validateNetplanYAML enforces a narrow netplan v2 allowlist before root apply.
func validateNetplanYAML(data []byte) error {
	if strings.TrimSpace(string(data)) == "" {
		return fmt.Errorf("netplan: empty yaml")
	}

	var document yaml.Node
	if err := yaml.Load(data, &document); err != nil {
		// Parser errors can include source fragments. Do not return them across
		// the privileged broker boundary because staged files may contain secrets.
		return fmt.Errorf("netplan: invalid yaml")
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fmt.Errorf("netplan: exactly one yaml document is required")
	}
	root := document.Content[0]
	if err := validateNetplanNode(root); err != nil {
		return err
	}
	rootEntries, err := netplanMapping(root, "document")
	if err != nil {
		return err
	}
	if len(rootEntries) != 1 {
		return fmt.Errorf("netplan: document must contain only the network key")
	}
	network, ok := rootEntries["network"]
	if !ok {
		return fmt.Errorf("netplan: missing network key")
	}

	networkEntries, err := netplanMapping(network, "network")
	if err != nil {
		return err
	}
	for key := range networkEntries {
		if !netplanAllowedNetworkKeys[key] {
			return fmt.Errorf("netplan: network key %q is not allowed", key)
		}
	}

	version, ok := networkEntries["version"]
	if !ok || version.Kind != yaml.ScalarNode || version.ShortTag() != "!!int" || version.Value != "2" {
		return fmt.Errorf("netplan: integer version 2 is required")
	}
	if renderer, ok := networkEntries["renderer"]; ok {
		if renderer.Kind != yaml.ScalarNode || renderer.ShortTag() != "!!str" ||
			(renderer.Value != "networkd" && renderer.Value != "NetworkManager") {
			return fmt.Errorf("netplan: renderer must be networkd or NetworkManager")
		}
	}

	hasInterfaces := false
	for key, value := range networkEntries {
		if !netplanInterfaceKeys[key] {
			continue
		}
		hasInterfaces = true
		if value.Kind != yaml.MappingNode {
			return fmt.Errorf("netplan: interface section %q must be a mapping", key)
		}
	}
	if !hasInterfaces {
		return fmt.Errorf("netplan: no allowed interface section")
	}
	return nil
}

func validateNetplanNode(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("netplan: invalid empty node")
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil || node.Anchor != "" {
		return fmt.Errorf("netplan: aliases and anchors are not allowed")
	}
	if node.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("netplan: explicit yaml tags are not allowed")
	}

	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("netplan: invalid mapping")
		}
		seen := make(map[string]bool, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return fmt.Errorf("netplan: mapping keys must be strings")
			}
			if key.Value == "<<" || key.ShortTag() == "!!merge" {
				return fmt.Errorf("netplan: yaml merge keys are not allowed")
			}
			if seen[key.Value] {
				return fmt.Errorf("netplan: duplicate mapping key %q", key.Value)
			}
			seen[key.Value] = true
			if netplanForbiddenKeys[key.Value] {
				return fmt.Errorf("netplan: key %q is not allowed", key.Value)
			}
			if key.Value == "type" && value.Kind == yaml.ScalarNode &&
				netplanForbiddenTypes[strings.ToLower(value.Value)] {
				return fmt.Errorf("netplan: tunnel device type is not allowed")
			}
		}
	}

	for _, child := range node.Content {
		if err := validateNetplanNode(child); err != nil {
			return err
		}
	}
	return nil
}

func netplanMapping(node *yaml.Node, name string) (map[string]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return nil, fmt.Errorf("netplan: %s must be a mapping", name)
	}
	entries := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		entries[node.Content[i].Value] = node.Content[i+1]
	}
	return entries, nil
}

func validateNetplanFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return validateNetplanYAML(b)
}
