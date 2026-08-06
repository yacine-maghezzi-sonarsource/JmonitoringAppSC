/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Logs monitoring alerts through Log4j 2.14.1.
 *
 * <p>Dependency risk: Log4Shell (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832).
 * The alert text originates from the HTTP request and flows unmodified into the logger, so a
 * {@code ${jndi:...}} lookup embedded in it is evaluated by the vulnerable runtime.
 */
public class AlertLoggingService {

    private static final Logger LOG = LogManager.getLogger(AlertLoggingService.class);

    public void recordAlert(String alertText) {
        // Tainted value interpolated by Log4j's message lookups.
        LOG.error("Monitoring alert received: {}", alertText);
    }
}
