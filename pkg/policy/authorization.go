// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import "strings"

type AuthorizationPolicy struct {
	Name   string              `json:"name"`
	Action string              `json:"action"`
	Rules  []AuthorizationRule `json:"rules"`
}

type AuthorizationRule struct {
	Sources []AuthorizationSource `json:"sources"`
}

type AuthorizationSource struct {
	Principals []string `json:"principals"`
}

type Decision struct {
	Allowed  bool
	DeniedBy string
}

func Authorize(policies []AuthorizationPolicy, principal string) Decision {
	hasAllow := false
	allowMatched := false
	for _, authorizationPolicy := range policies {
		matched := policyMatches(authorizationPolicy, principal)
		switch strings.ToUpper(authorizationPolicy.Action) {
		case "DENY":
			if matched {
				return Decision{DeniedBy: authorizationPolicy.Name}
			}
		case "ALLOW":
			hasAllow = true
			allowMatched = allowMatched || matched
		}
	}
	if hasAllow && !allowMatched {
		return Decision{DeniedBy: "implicit-deny"}
	}
	return Decision{Allowed: true}
}

func policyMatches(authorizationPolicy AuthorizationPolicy, principal string) bool {
	for _, rule := range authorizationPolicy.Rules {
		if len(rule.Sources) == 0 {
			return true
		}
		for _, source := range rule.Sources {
			if len(source.Principals) == 0 {
				return true
			}
			if matchesAnyPrincipal(principal, source.Principals) {
				return true
			}
		}
	}
	return false
}

func matchesAnyPrincipal(principal string, patterns []string) bool {
	if principal == "" {
		return false
	}
	for _, pattern := range patterns {
		if wildcardMatch(pattern, principal) {
			return true
		}
		if strings.HasPrefix(principal, "spiffe://") &&
			wildcardMatch(pattern, strings.TrimPrefix(principal, "spiffe://")) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, value string) bool {
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
