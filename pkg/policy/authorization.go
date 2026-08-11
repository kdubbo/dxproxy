// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type TLSVersion string

const (
	TLSVersion12 TLSVersion = "TLSV1_2"
	TLSVersion13 TLSVersion = "TLSV1_3"
)

func ParseOptionalTLSVersion(value string) (TLSVersion, error) {
	switch version := TLSVersion(strings.ToUpper(strings.TrimSpace(value))); version {
	case "":
		return "", nil
	case TLSVersion12, TLSVersion13:
		return version, nil
	default:
		return "", fmt.Errorf("unsupported minimum TLS version %q; want TLSV1_2 or TLSV1_3", value)
	}
}

func (v TLSVersion) TLSVersion() uint16 {
	if v == TLSVersion13 {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func tlsVersionPriority(version TLSVersion) int {
	if version == TLSVersion13 {
		return 2
	}
	if version == TLSVersion12 {
		return 1
	}
	return 0
}

type AuthorizationPolicy struct {
	Name   string              `json:"name"`
	Action string              `json:"action"`
	DryRun bool                `json:"dryRun"`
	Rules  []AuthorizationRule `json:"rules"`
}

type AuthorizationRule struct {
	Sources    []AuthorizationSource    `json:"sources"`
	Operations []AuthorizationOperation `json:"operations"`
	When       []AuthorizationCondition `json:"when"`
}

type AuthorizationSource struct {
	Principals           []string `json:"principals"`
	NotPrincipals        []string `json:"notPrincipals"`
	RequestPrincipals    []string `json:"requestPrincipals"`
	NotRequestPrincipals []string `json:"notRequestPrincipals"`
	Namespaces           []string `json:"namespaces"`
	NotNamespaces        []string `json:"notNamespaces"`
	ServiceAccounts      []string `json:"serviceAccounts"`
	NotServiceAccounts   []string `json:"notServiceAccounts"`
	IPBlocks             []string `json:"ipBlocks"`
	NotIPBlocks          []string `json:"notIpBlocks"`
	RemoteIPBlocks       []string `json:"remoteIpBlocks"`
	NotRemoteIPBlocks    []string `json:"notRemoteIpBlocks"`
}

type AuthorizationOperation struct {
	Hosts      []string `json:"hosts"`
	NotHosts   []string `json:"notHosts"`
	Ports      []string `json:"ports"`
	NotPorts   []string `json:"notPorts"`
	Methods    []string `json:"methods"`
	NotMethods []string `json:"notMethods"`
	Paths      []string `json:"paths"`
	NotPaths   []string `json:"notPaths"`
}

type AuthorizationCondition struct {
	Key       string   `json:"key"`
	Values    []string `json:"values"`
	NotValues []string `json:"notValues"`
}

type ConnectionAttributes struct {
	Principal      string
	Namespace      string
	ServiceAccount string
	SourceIP       netip.Addr
	Port           int
}

type Decision struct {
	Allowed       bool
	DeniedBy      string
	AuditPolicies []string
}

func Authorize(policies []AuthorizationPolicy, attributes ConnectionAttributes) Decision {
	decision := Decision{Allowed: true}
	hasAllow := false
	allowMatched := false
	for _, policy := range policies {
		matched := policyMatches(policy, attributes)
		if policy.DryRun {
			if matched {
				decision.AuditPolicies = append(decision.AuditPolicies, policy.Name)
			}
			continue
		}
		switch strings.ToUpper(policy.Action) {
		case "DENY":
			if matched {
				decision.Allowed = false
				decision.DeniedBy = policy.Name
				return decision
			}
		case "ALLOW":
			hasAllow = true
			allowMatched = allowMatched || matched
		}
	}
	if hasAllow && !allowMatched {
		decision.Allowed = false
		decision.DeniedBy = "implicit-deny"
	}
	return decision
}

func policyMatches(policy AuthorizationPolicy, attributes ConnectionAttributes) bool {
	for _, rule := range policy.Rules {
		if ruleMatches(rule, attributes) {
			return true
		}
	}
	return false
}

func ruleMatches(rule AuthorizationRule, attributes ConnectionAttributes) bool {
	if len(rule.Sources) > 0 {
		matched := false
		for _, source := range rule.Sources {
			if sourceMatches(source, attributes) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(rule.Operations) > 0 {
		matched := false
		for _, operation := range rule.Operations {
			if operationMatches(operation, attributes) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, condition := range rule.When {
		if !conditionMatches(condition, attributes) {
			return false
		}
	}
	return true
}

func sourceMatches(source AuthorizationSource, attributes ConnectionAttributes) bool {
	if len(source.RequestPrincipals) > 0 {
		return false
	}
	if !matchesPositiveAndNegative(attributes.Principal, source.Principals, source.NotPrincipals) ||
		!matchesPositiveAndNegative("", nil, source.NotRequestPrincipals) ||
		!matchesPositiveAndNegative(attributes.Namespace, source.Namespaces, source.NotNamespaces) ||
		!matchesPositiveAndNegative(attributes.ServiceAccount, source.ServiceAccounts, source.NotServiceAccounts) ||
		!matchesIP(attributes.SourceIP, source.IPBlocks, source.NotIPBlocks) ||
		!matchesIP(attributes.SourceIP, source.RemoteIPBlocks, source.NotRemoteIPBlocks) {
		return false
	}
	return true
}

func operationMatches(operation AuthorizationOperation, attributes ConnectionAttributes) bool {
	if len(operation.Hosts)+len(operation.NotHosts)+len(operation.Methods)+len(operation.NotMethods)+
		len(operation.Paths)+len(operation.NotPaths) > 0 {
		return false
	}
	return matchesPositiveAndNegative(strconv.Itoa(attributes.Port), operation.Ports, operation.NotPorts)
}

func conditionMatches(condition AuthorizationCondition, attributes ConnectionAttributes) bool {
	var value string
	switch condition.Key {
	case "source.principal":
		value = attributes.Principal
	case "source.namespace":
		value = attributes.Namespace
	case "source.serviceAccount":
		value = attributes.ServiceAccount
	case "source.ip":
		value = attributes.SourceIP.String()
	case "destination.port":
		value = strconv.Itoa(attributes.Port)
	default:
		return false
	}
	return matchesPositiveAndNegative(value, condition.Values, condition.NotValues)
}

func matchesPositiveAndNegative(value string, positive, negative []string) bool {
	if len(positive) > 0 && !matchesAny(value, positive) {
		return false
	}
	return !matchesAny(value, negative)
}

func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if wildcardMatch(pattern, value) {
			return true
		}
		if strings.HasPrefix(value, "spiffe://") && wildcardMatch(pattern, strings.TrimPrefix(value, "spiffe://")) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = strings.TrimPrefix(value, parts[0])
	for index, part := range parts[1:] {
		if part == "" {
			continue
		}
		position := strings.Index(value, part)
		if position < 0 || (index == len(parts)-2 && !strings.HasSuffix(value, part)) {
			return false
		}
		value = value[position+len(part):]
	}
	return true
}

func matchesIP(address netip.Addr, positive, negative []string) bool {
	if len(positive) > 0 && !ipInBlocks(address, positive) {
		return false
	}
	return !ipInBlocks(address, negative)
}

func ipInBlocks(address netip.Addr, blocks []string) bool {
	if !address.IsValid() {
		return false
	}
	for _, block := range blocks {
		if prefix, err := netip.ParsePrefix(block); err == nil && prefix.Contains(address) {
			return true
		}
		if candidate, err := netip.ParseAddr(block); err == nil && candidate == address {
			return true
		}
	}
	return false
}

func sortAuthorizationPolicies(policies []AuthorizationPolicy) {
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Name == policies[j].Name {
			return policies[i].Action < policies[j].Action
		}
		return policies[i].Name < policies[j].Name
	})
}
