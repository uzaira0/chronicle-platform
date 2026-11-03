package com.example

import com.openlattice.chronicle.util.ClientIpResolver

class CopiedTrustedProxyDefaults(
    // ruleid: trusted-proxy-cidr-single-owner
    val trustedProxyCidrs: List<String> = listOf("172.16.0.0/12"),
)

class SharedTrustedProxyDefaults(
    val trustedProxyCidrs: List<String> = ClientIpResolver.LOOPBACK_PROXY_CIDRS,
)

fun permittedDeploymentRanges(configuredRanges: String?): List<String> =
    ClientIpResolver.deploymentTrustedProxyCidrs(ClientIpResolver.LOOPBACK_PROXY_CIDRS, configuredRanges)

private val whitelistedIps = listOf("127.0.0.1")
private val PRIVATE_IP_RANGES = listOf("10.0.0.0/8", "172.16.0.0/12")
