/*
 * This file is part of Dependency-Track plugin for Fortify SSC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.integrations.fortifyssc;

import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import org.dependencytrack.api.model.Analysis;
import org.dependencytrack.api.model.Component;
import org.dependencytrack.api.model.Finding;
import org.dependencytrack.api.model.Project;
import org.dependencytrack.api.model.Severity;
import org.dependencytrack.api.model.Vulnerability;
import org.dependencytrack.api.parsers.FindingParser;
import org.dependencytrack.api.util.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.Date;

import static org.dependencytrack.integrations.fortifyssc.CustomVulnerabilityAttribute.*;

public class DependencyTrackParserPlugin implements ParserPlugin<CustomVulnerabilityAttribute> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyTrackParserPlugin.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void start() {
        LOGGER.info("DependencyTrackParserPlugin plugin is starting");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop() {
        LOGGER.info("DependencyTrackParserPlugin plugin is stopping");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<CustomVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return CustomVulnerabilityAttribute.class;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) throws IOException {
        final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
        final FindingParser findingParser = new FindingParser(content).parse();
        try {
            scanBuilder.setScanDate(DateUtil.fromISO8601(findingParser.getMeta().getTimestamp()));
        } catch (ParseException e) {
            scanBuilder.setScanDate(new Date());
        }
        scanBuilder.setEngineVersion(findingParser.getMeta().getVersion());
        scanBuilder.completeScan();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh) throws IOException {
        final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
        final FindingParser findingParser = new FindingParser(content).parse();
        for (Finding finding: findingParser.getFindings()) {
            final StaticVulnerabilityBuilder vb = vh.startStaticVulnerability(getUniqueId(finding));
            populateVulnerability(vb, finding, findingParser.getProject());
            vb.completeVulnerability();
        }
    }

    /**
     * Creates a Fortify vulnerability from the specified Dependency-Track Finding.
     * @param vb a StaticVulnerabilityBuilder to create a Fortify vulnerability with
     * @param finding the Finding to create the vulnerability from
     */
    private void populateVulnerability(final StaticVulnerabilityBuilder vb, final Finding finding, final Project project) {
        final Component comp = finding.getComponent();
        final Vulnerability vuln = finding.getVulnerability();
        final Analysis analysis = finding.getAnalysis();

        // Set builtin attributes
        vb.setCategory("3rd Party Component");
        vb.setSubCategory("");
        vb.setFileName(createFilename(comp));
        vb.setVulnerabilityAbstract(vuln.getTitle());
        vb.setPriority(toFriority(vuln.getSeverity()));

        // Confidence varies based on analyzer used. NPM Audit and OSSIndex are both high (5) confidence
        // Confidence of Dependency-Check findings will vary dramatically. Compromise on confidence score.
        vb.setConfidence(3.5f);

        // Impact will also vary depending on if the finding is valid and if the application is suseptable
        // to this vulnerability. Compromise on impact score.
        vb.setImpact(3.5f);

        // PROJECT attributes
        if (project.getName() != null) {
            vb.setStringCustomAttributeValue(PROJECT_NAME, project.getName());
        }
        if (project.getVersion() != null) {
            vb.setStringCustomAttributeValue(PROJECT_VERSION, project.getVersion());
        }

        // COMPONENT attributes
        if (comp.getName() != null) {
            vb.setStringCustomAttributeValue(COMPONENT_NAME, comp.getName());
        }
        if (comp.getGroup() != null) {
            vb.setStringCustomAttributeValue(COMPONENT_GROUP, comp.getGroup());
        }
        if (comp.getVersion() != null) {
            vb.setStringCustomAttributeValue(COMPONENT_VERSION, comp.getVersion());
        }
        if (comp.getPurl() != null) {
            vb.setStringCustomAttributeValue(COMPONENT_PURL, comp.getPurl());
        }

        // VULNERABILITY attributes
        if (vuln.getSource() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_SOURCE, vuln.getSource());
        }
        if (vuln.getVulnId() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_ID, vuln.getVulnId());
        }
        if (vuln.getDescription() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_DESCRIPTION, vuln.getDescription());
        }
        if (vuln.getRecommendation() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_RECOMMENDATION, vuln.getRecommendation());
        }
        if (vuln.getCweId() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_CWE_ID, String.valueOf(vuln.getCweId()));
        }
        if (vuln.getCweName() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_CWE_NAME, vuln.getCweName());
        }

        // ANALYSIS attributes
        if (analysis.getState() != null) {
            vb.setStringCustomAttributeValue(ANALYSIS_STATE, analysis.getState());
        }

        // set long string custom attributes
        if (vuln.getDescription() != null) {
            vb.setStringCustomAttributeValue(DESCRIPTION, vuln.getDescription());
        }
    }

    /**
     * Ideally, the PackageURL would be used (if available) for the filename, but
     * SSC contains input validation that sanitizes the input stripping off the first
     * half of the purl.
     * @param component A component to create a pseudo filename for
     * @return a String
     */
    private String createFilename(Component component) {
        String filename = "";
        if (component.getGroup() != null) {
            filename = component.getGroup() + ":";
        }
        filename += component.getName() + ":" + component.getVersion();
        return filename;
    }

    /**
     * Each Findings has a matrix which uniquely identifies the vulnerability. The matrix
     * consists of three UUIDs separated by (:), each UUID representing a unique identifier
     * for the project, component, and vulnerability. The length of the matrix exceeds the
     * maximum length of the instanceId field in SSC, but it only needs to be unique with
     * a scan. So omitting the project and shortening the sequence provides both consistency
     * and uniqueness on a per-scan basis.
     * @param finding the finding to generate a unique ID from
     * @return a String representation of the ID
     */
    private String getUniqueId(Finding finding)  {
        return (finding.getComponent().getUuid() + finding.getVulnerability().getUuid()).replace("-", "");
    }

    /**
     * Converts Dependency-Track Severity to Fortify Priority Order.
     * @param severity the Severity to convert
     * @return a Fortify Priority
     */
    private BasicVulnerabilityBuilder.Priority toFriority(final Severity severity) {
        if (Severity.CRITICAL == severity) {
            return BasicVulnerabilityBuilder.Priority.Critical;
        } else if (Severity.HIGH == severity) {
            return BasicVulnerabilityBuilder.Priority.High;
        } else if (Severity.MEDIUM == severity) {
            return BasicVulnerabilityBuilder.Priority.Medium;
        } else if (Severity.LOW == severity) {
            return BasicVulnerabilityBuilder.Priority.Low;
        }
        return BasicVulnerabilityBuilder.Priority.Low;
    }
}