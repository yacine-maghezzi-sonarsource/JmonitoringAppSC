/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import com.thoughtworks.xstream.XStream;

/**
 * Restores saved dashboard layouts through XStream 1.4.5.
 *
 * <p>Dependency risk: XML deserialization remote code execution (CVE-2021-39144, CVE-2021-21344 and
 * roughly twenty further RCE CVEs in the 1.4.x line). No security framework / allow-list is
 * configured, so {@link XStream#fromXML(String)} on untrusted XML instantiates arbitrary types.
 */
public class DashboardStateService {

    private final XStream xstream = new XStream();

    public Object restore(String xml) {
        // Tainted XML deserialized with no type allow-list.
        return xstream.fromXML(xml);
    }
}
