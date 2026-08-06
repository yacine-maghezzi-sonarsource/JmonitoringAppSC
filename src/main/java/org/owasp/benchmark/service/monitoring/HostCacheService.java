/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import com.google.common.io.Files;
import java.io.File;

/**
 * Allocates scratch directories for cached host metrics through Guava 24.1.1-jre.
 *
 * <p>Dependency risk: insecure temporary directory creation (CVE-2020-8908) plus further CVEs in
 * this Guava line (CVE-2023-2976, CVE-2018-10237). {@link Files#createTempDir()} creates a
 * world-readable directory with predictable permissions.
 */
public class HostCacheService {

    public File allocateCacheDir() {
        // Vulnerable temp-directory factory.
        return Files.createTempDir();
    }
}
