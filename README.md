# dxproxy

The standalone inbound sidecar has been removed.

Dubbo Inherent is proxyless: the original application container consumes the
xDS bootstrap, runtime policy, certificates and telemetry configuration
directly. No dxproxy image or additional workload container is required.
