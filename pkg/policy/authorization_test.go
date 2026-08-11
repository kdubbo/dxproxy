// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import (
	"net/netip"
	"testing"
)

func TestAuthorizeL4Policies(t *testing.T) {
	attributes := ConnectionAttributes{
		Principal:      "spiffe://cluster.local/ns/default/sa/client",
		Namespace:      "default",
		ServiceAccount: "default/client",
		SourceIP:       netip.MustParseAddr("203.0.113.10"),
		Port:           8080,
	}
	policies := []AuthorizationPolicy{
		{
			Name:   "audit-client",
			Action: "ALLOW",
			DryRun: true,
			Rules: []AuthorizationRule{{Sources: []AuthorizationSource{{
				Principals: []string{"cluster.local/ns/default/sa/*"},
			}}}},
		},
		{
			Name:   "deny-private",
			Action: "DENY",
			Rules: []AuthorizationRule{{Sources: []AuthorizationSource{{
				IPBlocks: []string{"10.0.0.0/8"},
			}}}},
		},
		{
			Name:   "allow-client",
			Action: "ALLOW",
			Rules: []AuthorizationRule{{
				Sources: []AuthorizationSource{{
					Namespaces:      []string{"default"},
					ServiceAccounts: []string{"default/client"},
					IPBlocks:        []string{"203.0.113.0/24"},
				}},
				Operations: []AuthorizationOperation{{Ports: []string{"8080"}}},
			}},
		},
	}

	decision := Authorize(policies, attributes)
	if !decision.Allowed || len(decision.AuditPolicies) != 1 || decision.AuditPolicies[0] != "audit-client" {
		t.Fatalf("decision = %#v", decision)
	}

	attributes.SourceIP = netip.MustParseAddr("10.1.2.3")
	decision = Authorize(policies, attributes)
	if decision.Allowed || decision.DeniedBy != "deny-private" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestAuthorizeDoesNotTreatL7RuleAsConnectionMatch(t *testing.T) {
	decision := Authorize([]AuthorizationPolicy{{
		Name:   "allow-get",
		Action: "ALLOW",
		Rules: []AuthorizationRule{{
			Operations: []AuthorizationOperation{{Methods: []string{"GET"}}},
		}},
	}}, ConnectionAttributes{Port: 8080})
	if decision.Allowed || decision.DeniedBy != "implicit-deny" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestTLSVersionDefaultsAndParsing(t *testing.T) {
	if TLSVersion("").TLSVersion() != 0x0303 {
		t.Fatalf("default TLS version = %#x", TLSVersion("").TLSVersion())
	}
	version, err := ParseOptionalTLSVersion("TLSV1_3")
	if err != nil || version.TLSVersion() != 0x0304 {
		t.Fatalf("TLSV1_3 = %q, %v", version, err)
	}
}
