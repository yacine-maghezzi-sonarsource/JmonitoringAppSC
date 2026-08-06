/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import org.apache.commons.text.StringSubstitutor;

/**
 * Renders metric label templates through Apache Commons Text 1.9.
 *
 * <p>Dependency risk: Text4Shell (CVE-2022-42889). The default {@link StringSubstitutor} resolves
 * {@code ${script:...}}, {@code ${dns:...}} and {@code ${url:...}} lookups, so an attacker-supplied
 * template string reaches code execution.
 */
public class MetricTemplateService {

    public String render(String template) {
        StringSubstitutor substitutor = new StringSubstitutor();
        // Tainted template interpolated with the dangerous default lookups enabled.
        return substitutor.replace(template);
    }
}
