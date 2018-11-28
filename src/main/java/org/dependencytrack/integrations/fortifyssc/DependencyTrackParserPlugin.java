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
import org.dependencytrack.integrations.fortifyssc.model.Analysis;
import org.dependencytrack.integrations.fortifyssc.model.Component;
import org.dependencytrack.integrations.fortifyssc.model.Finding;
import org.dependencytrack.integrations.fortifyssc.model.Project;
import org.dependencytrack.integrations.fortifyssc.model.Severity;
import org.dependencytrack.integrations.fortifyssc.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import static org.dependencytrack.integrations.fortifyssc.CustomVulnerabilityAttribute.*;

public class DependencyTrackParserPlugin implements ParserPlugin<CustomVulnerabilityAttribute> {

    private static final Logger LOGGER = LoggerFactory.getLogger(DependencyTrackParserPlugin.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void start() throws Exception {
        LOGGER.info("DependencyTrackParserPlugin plugin is starting");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void stop() throws Exception {
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
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) {
        scanBuilder.setScanDate(new Date()); //todo change this
        scanBuilder.setEngineVersion("3.4.0"); //todo change this
        scanBuilder.completeScan();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh) throws IOException {
        final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
        final FindingParser parser = new FindingParser(content).parse();
        for (Finding finding: parser.getFindings()) {
            final StaticVulnerabilityBuilder vb = vh.startStaticVulnerability(getUniqueId(finding));
            populateVulnerability(vb, finding);
            vb.completeVulnerability();
        }
    }

    /**
     * Creates a Fortify vulnerability from the specified Dependency-Track Finding.
     * @param vb a StaticVulnerabilityBuilder to create a Fortify vulnerability with
     * @param finding the Finding to create the vulnerability from
     */
    private void populateVulnerability(final StaticVulnerabilityBuilder vb, final Finding finding) {
        final Project project = finding.getProject();
        final Component comp = finding.getComponent();
        final Vulnerability vuln = finding.getVulnerability();
        final Analysis analysis = finding.getAnalysis();

        // Set builtin attributes
        vb.setCategory("3rd Party Component");

        //vb.setFileName(fn.getFileName()); // todo: use PURL??????
        vb.setVulnerabilityAbstract(vuln.getTitle());

        // Confidence varies based on analyzer used. NPM Audit and OSSIndex are both high (5) confidence
        // Confidence of Dependency-Check findings will vary dramatically. Compromise on confidence score.
        vb.setConfidence(3.5f);

        // Impact will also vary depending on if the finding is valid and if the application is suseptable
        // to this vulnerability. Compromise on impact score.
        vb.setImpact(3.5f);

        // Converts Dependency-Track severity to Fortify Priority Order
        vb.setPriority(toFriority(vuln.getSeverity()));

        // PROJECT attributes
        // NOTE: Project was not included in the response in Dependency-Track v3.3.x, therefore it may be null.
        if (project != null) {
            if (project.getUuid() != null) {
                //vb.setStringCustomAttributeValue(PROJECT_UUID, project.getUuid());
            }
            if (project.getName() != null) {
                //vb.setStringCustomAttributeValue(PROJECT_NAME, project.getName());
            }
            if (project.getVersion() != null) {
                //vb.setStringCustomAttributeValue(PROJECT_VERSION, project.getVersion());
            }
        }

        // COMPONENT attributes
        if (comp.getUuid() != null) {
            //vb.setStringCustomAttributeValue(COMPONENT_UUID, comp.getUuid());
        }
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
        if (vuln.getUuid() != null) {
            //vb.setStringCustomAttributeValue(VULNERABILITY_UUID, vuln.getUuid());
        }
        if (vuln.getSource() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_SOURCE, vuln.getSource());
        }
        if (vuln.getVulnId() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_ID, vuln.getVulnId());
        }
        if (vuln.getTitle() != null) {
            //vb.setStringCustomAttributeValue(VULNERABILITY_TITLE, vuln.getTitle());
        }
        if (vuln.getSubtitle() != null) {
            //vb.setStringCustomAttributeValue(VULNERABILITY_SUBTITLE, vuln.getSubtitle());
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