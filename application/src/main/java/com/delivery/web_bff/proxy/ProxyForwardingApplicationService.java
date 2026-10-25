package com.delivery.web_bff.proxy;

import com.delivery.web_bff.application.api.Ports;
import com.delivery.web_bff.application.api.UseCases;
import com.delivery.web_bff.domain.session.ApiProxyRejectedException;
import java.util.List;
import java.util.Map;

/** Authenticates and sanitizes proxy traffic before delegating to a gateway adapter. */
public final class ProxyForwardingApplicationService implements UseCases.ProxyForwarding {
    // HTTP header names are case-insensitive and the Gateway hands them over in
    // lower case, so the allowlist is matched ignoring case and re-emitted with
    // its canonical spelling.
    private static final Map<String, String> REQUEST_HEADERS = java.util.stream.Stream.of("Accept", "Content-Type",
            "Idempotency-Key", "If-Match", "If-None-Match", "X-Correlation-ID")
            .collect(java.util.stream.Collectors.toUnmodifiableMap(h -> h.toLowerCase(java.util.Locale.ROOT), h -> h));
    private final UseCases.ApiPolicyEvaluation policy;
    private final UseCases.AccessTokenResolution access;
    private final Ports.ProxyForwarding gateway;

    public ProxyForwardingApplicationService(UseCases.ApiPolicyEvaluation policy,
            UseCases.AccessTokenResolution access, Ports.ProxyForwarding gateway) {
        this.policy = policy; this.access = access; this.gateway = gateway;
    }

    @Override
    public Ports.ForwardedResponse execute(UseCases.ProxyRequest request) {
        if (request == null || !policy.execute(request.method(), request.path()))
            throw new ApiProxyRejectedException("API path or method is not allowed");
        boolean mutation = switch (request.method()) {
            case POST, PUT, PATCH, DELETE -> true;
            case GET, HEAD, OPTIONS -> false;
        };
        String bearer = access.execute(request.rawSessionId(), request.csrfToken(), mutation);
        Map<String, List<String>> safe = new java.util.LinkedHashMap<>();
        if (request.headers() != null) {
            request.headers().forEach((name, values) -> {
                String canonical = name == null ? null : REQUEST_HEADERS.get(name.toLowerCase(java.util.Locale.ROOT));
                if (canonical != null && values != null) safe.merge(canonical, List.copyOf(values),
                        (a, b) -> java.util.stream.Stream.concat(a.stream(), b.stream()).toList());
            });
        }
        return gateway.forward(request.method(), request.path(), request.query(), Map.copyOf(safe),
                request.body() == null ? new byte[0] : request.body(), bearer);
    }

}
