// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import "testing"

func TestAuthorizeWorkloadPrincipal(t *testing.T) {
	policies := []AuthorizationPolicy{
		{
			Name:   "deny-other-namespace",
			Action: "DENY",
			Rules: []AuthorizationRule{{Sources: []AuthorizationSource{{
				Principals: []string{"cluster.local/ns/other/*"},
			}}}},
		},
		{
			Name:   "allow-orders",
			Action: "ALLOW",
			Rules: []AuthorizationRule{{Sources: []AuthorizationSource{{
				Principals: []string{"cluster.local/ns/orders/sa/*"},
			}}}},
		},
	}

	tests := []struct {
		name      string
		principal string
		allowed   bool
		deniedBy  string
	}{
		{name: "allowed SPIFFE identity", principal: "spiffe://cluster.local/ns/orders/sa/client", allowed: true},
		{name: "explicit deny", principal: "spiffe://cluster.local/ns/other/sa/client", deniedBy: "deny-other-namespace"},
		{name: "implicit deny", principal: "spiffe://cluster.local/ns/default/sa/client", deniedBy: "implicit-deny"},
		{name: "plaintext cannot match wildcard", deniedBy: "implicit-deny"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Authorize(policies, test.principal)
			if decision.Allowed != test.allowed || decision.DeniedBy != test.deniedBy {
				t.Fatalf("Authorize() = %+v, want allowed=%v deniedBy=%q", decision, test.allowed, test.deniedBy)
			}
		})
	}
}

func TestAuthorizeWithoutPolicies(t *testing.T) {
	if decision := Authorize(nil, ""); !decision.Allowed {
		t.Fatalf("Authorize() = %+v, want allowed", decision)
	}
}
