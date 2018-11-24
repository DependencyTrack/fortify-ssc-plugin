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

    @Override
    public void start() throws Exception {
        LOGGER.info("DependencyTrackParserPlugin plugin is starting");
    }

    @Override
    public void stop() throws Exception {
        LOGGER.info("DependencyTrackParserPlugin plugin is stopping");
    }

    @Override
    public Class<CustomVulnerabilityAttribute> getVulnerabilityAttributesClass() {
        return CustomVulnerabilityAttribute.class;
    }

    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) {
        //parseJson(scanData, scanBuilder, this::parseScanInternal);
        scanBuilder.setScanDate(new Date()); //todo change this
        scanBuilder.setEngineVersion("3.4.0"); //todo change this
        scanBuilder.completeScan();
    }

    @Override
    public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh) throws IOException {
        //parseJson(scanData, vh, this::parseVulnerabilitiesInternal);
        final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
        final FindingParser parser = new FindingParser(content).parse();

        for (Finding finding: parser.getFindings()) {
            final StaticVulnerabilityBuilder vb = vh.startStaticVulnerability(finding.getMatrix());
            populateVulnerability(vb, finding);
            vb.completeVulnerability();
        }
    }

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
                vb.setStringCustomAttributeValue(PROJECT_UUID, project.getUuid());
            }
            if (project.getName() != null) {
                vb.setStringCustomAttributeValue(PROJECT_NAME, project.getName());
            }
            if (project.getVersion() != null) {
                vb.setStringCustomAttributeValue(PROJECT_VERSION, project.getVersion());
            }
        }

        // COMPONENT attributes
        if (comp.getUuid() != null) {
            vb.setStringCustomAttributeValue(COMPONENT_UUID, comp.getUuid());
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
            vb.setStringCustomAttributeValue(VULNERABILITY_UUID, vuln.getUuid());
        }
        if (vuln.getSource() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_SOURCE, vuln.getSource());
        }
        if (vuln.getVulnId() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_ID, vuln.getVulnId());
        }
        if (vuln.getTitle() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_TITLE, vuln.getTitle());
        }
        if (vuln.getSubtitle() != null) {
            vb.setStringCustomAttributeValue(VULNERABILITY_SUBTITLE, vuln.getSubtitle());
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