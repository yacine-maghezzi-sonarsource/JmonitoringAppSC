/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

/**
 * Keeps a registry of active monitoring probes, keyed through Commons Collections 3.2.1.
 *
 * <p>Dependency risk: {@code InvokerTransformer} deserialization gadget (CVE-2015-6420,
 * CVE-2015-7501). This is the exact artifact excluded from {@code apacheds-core}, {@code
 * shared-ldap} and {@code hibernate-core} in the POM; declaring it directly and wiring a {@link
 * TransformedMap} around {@link InvokerTransformer} reintroduces the gadget on the classpath.
 */
@SuppressWarnings("unchecked")
public class ProbeRegistryService {

    private final Map<String, Object> probes;

    public ProbeRegistryService() {
        Transformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
        this.probes = TransformedMap.decorate(new HashMap(), null, transformer);
    }

    public void register(String probeName, Object descriptor) {
        // Value passes through the InvokerTransformer gadget on insertion.
        probes.put(probeName, descriptor);
    }

    public int size() {
        return probes.size();
    }
}
