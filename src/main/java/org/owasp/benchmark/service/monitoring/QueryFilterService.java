/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this class deliberately reaches a vulnerable third-party API on untrusted input so
 * that Software Composition Analysis reports a reachable dependency risk. Do not deploy.
 */
package org.owasp.benchmark.service.monitoring;

import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

/**
 * Parses dashboard query filters through json-smart 2.4.7.
 *
 * <p>Dependency risk: stack exhaustion / denial of service on deeply nested JSON (CVE-2023-1370,
 * CVE-2021-31684). The untrusted filter expression is parsed with no depth limit.
 */
public class QueryFilterService {

    public Object parseFilter(String filter) throws ParseException {
        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);
        // Tainted expression parsed without a nesting-depth guard.
        return parser.parse(filter);
    }
}
