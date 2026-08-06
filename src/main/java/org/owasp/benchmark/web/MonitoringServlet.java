/**
 * JMonitoringAppSC - monitoring subsystem.
 *
 * <p>WARNING: this servlet feeds untrusted HTTP input straight into the monitoring services, each
 * of which reaches a known-vulnerable dependency. It exists so Software Composition Analysis has a
 * realistic HTTP entry point to report reachable dependency risks against. Do not deploy.
 *
 * <p>Layering: this is a Presentation-tier component (package {@code ...web}) and only depends on
 * the Business tier (package {@code ...service.monitoring}), per architecture.json.
 */
package org.owasp.benchmark.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.benchmark.service.monitoring.AlertLoggingService;
import org.owasp.benchmark.service.monitoring.ArchiveImportService;
import org.owasp.benchmark.service.monitoring.DashboardStateService;
import org.owasp.benchmark.service.monitoring.HostCacheService;
import org.owasp.benchmark.service.monitoring.MetricTemplateService;
import org.owasp.benchmark.service.monitoring.MetricsStoreService;
import org.owasp.benchmark.service.monitoring.MonitorConfigService;
import org.owasp.benchmark.service.monitoring.ProbeRegistryService;
import org.owasp.benchmark.service.monitoring.QueryFilterService;
import org.owasp.benchmark.service.monitoring.SensorPayloadService;

@WebServlet(value = "/monitoring/dispatch")
public class MonitoringServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/plain;charset=UTF-8");
        PrintWriter out = response.getWriter();

        String action = request.getParameter("action");
        String payload = request.getParameter("payload");
        if (action == null) {
            action = "";
        }
        if (payload == null) {
            payload = "";
        }

        try {
            switch (action) {
                case "alert":
                    new AlertLoggingService().recordAlert(payload);
                    out.println("alert logged");
                    break;
                case "template":
                    out.println(new MetricTemplateService().render(payload));
                    break;
                case "sensor":
                    out.println(new SensorPayloadService().parsePayload(payload));
                    break;
                case "config":
                    out.println(new MonitorConfigService().loadConfig(payload));
                    break;
                case "dashboard":
                    out.println(new DashboardStateService().restore(payload));
                    break;
                case "probe":
                    ProbeRegistryService registry = new ProbeRegistryService();
                    registry.register(payload, payload);
                    out.println("probes: " + registry.size());
                    break;
                case "cache":
                    out.println(new HostCacheService().allocateCacheDir().getAbsolutePath());
                    break;
                case "store":
                    new MetricsStoreService().openStore(payload).close();
                    out.println("store opened");
                    break;
                case "archive":
                    out.println(
                            new ArchiveImportService()
                                    .listEntries(payload.getBytes("UTF-8")));
                    break;
                case "filter":
                    out.println(new QueryFilterService().parseFilter(payload));
                    break;
                default:
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    out.println("unknown action");
            }
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
