/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Opens the embedded metrics database through the H2 1.4.199 driver.
 *
 * <p>Dependency risk: JDBC URL abuse leading to RCE (CVE-2021-42392, CVE-2022-23221) and
 * information disclosure (CVE-2018-10054). The attacker-controlled fragment is concatenated into
 * the JDBC URL, where an {@code INIT=...} clause runs arbitrary SQL/Java at connection time.
 */
public class MetricsStoreService {

    static {
        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("H2 driver missing", e);
        }
    }

    public Connection openStore(String urlFragment) throws SQLException {
        // Tainted fragment concatenated into the JDBC URL (enables the INIT vector).
        String url = "jdbc:h2:mem:metrics;" + urlFragment;
        return DriverManager.getConnection(url, "sa", "");
    }
}
