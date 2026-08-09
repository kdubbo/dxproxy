# dxproxy

dxproxy is the standalone inbound proxy for Dubbo Inherent mesh. It terminates inbound mTLS,
applies the workload's inbound mTLS mode, and proxies the resulting byte stream
to the local application.
