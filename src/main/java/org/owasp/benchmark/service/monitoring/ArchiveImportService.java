/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;

/**
 * Imports uploaded metric archives through Apache Commons Compress 1.20.
 *
 * <p>Dependency risk: archive-parsing denial of service (CVE-2021-35515, CVE-2021-35516,
 * CVE-2021-35517, CVE-2021-36090). A crafted archive drives excessive CPU/memory allocation while
 * the entries are enumerated below.
 */
public class ArchiveImportService {

    public List<String> listEntries(byte[] archive) throws IOException {
        List<String> names = new ArrayList<>();
        // Tainted bytes parsed by the vulnerable archive reader.
        try (ZipArchiveInputStream in =
                new ZipArchiveInputStream(new ByteArrayInputStream(archive))) {
            ZipArchiveEntry entry;
            while ((entry = in.getNextZipEntry()) != null) {
                names.add(entry.getName());
            }
        }
        return names;
    }
}
