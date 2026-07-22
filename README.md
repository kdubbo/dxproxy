# dxplane

dxplane is the standalone Dubbo xDS data plane. It terminates inbound mTLS,
applies the workload's inbound mTLS mode, and proxies the resulting byte stream
to the local application.
