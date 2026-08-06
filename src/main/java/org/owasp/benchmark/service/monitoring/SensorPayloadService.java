/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

/**
 * Parses sensor payloads through jackson-databind 2.9.10.1.
 *
 * <p>Dependency risk: polymorphic deserialization gadget chains (CVE-2020-36518, CVE-2019-20330,
 * CVE-2019-16942, CVE-2019-16943, CVE-2019-14540). Default typing is enabled and the untrusted JSON
 * is bound to {@link Object}, allowing an attacker to instantiate gadget classes by type hint.
 */
@SuppressWarnings("deprecation")
public class SensorPayloadService {

    private final ObjectMapper mapper = new ObjectMapper();

    public SensorPayloadService() {
        // The setting that makes gadget-chain deserialization possible.
        mapper.enableDefaultTyping();
    }

    public Object parsePayload(String json) throws IOException {
        // Tainted JSON deserialized with polymorphic typing.
        return mapper.readValue(json, Object.class);
    }
}
