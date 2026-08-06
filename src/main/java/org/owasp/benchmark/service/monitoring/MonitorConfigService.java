/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import org.yaml.snakeyaml.Yaml;

/**
 * Loads monitor configuration through SnakeYAML 1.30.
 *
 * <p>Dependency risk: unsafe YAML construction (CVE-2022-1471, CVE-2022-38752, CVE-2022-25857). The
 * default {@link Yaml} constructor honours {@code !!} type tags, so an attacker-supplied document
 * can instantiate arbitrary classes.
 */
public class MonitorConfigService {

    public Object loadConfig(String yaml) {
        // Tainted document parsed with the unsafe default constructor.
        return new Yaml().load(yaml);
    }
}
