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

import org.dependencytrack.integrations.fortifyssc.model.Analysis;
import org.dependencytrack.integrations.fortifyssc.model.Component;
import org.dependencytrack.integrations.fortifyssc.model.Finding;
import org.dependencytrack.integrations.fortifyssc.model.Project;
import org.dependencytrack.integrations.fortifyssc.model.Severity;
import org.dependencytrack.integrations.fortifyssc.model.Vulnerability;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.InputStream;
import java.util.ArrayList;

public class FindingParser {

    private final InputStream jsonResponseInputStream;
    private ArrayList<Finding> findings;

    public FindingParser(InputStream jsonResponseInputStream) {
        this.jsonResponseInputStream = jsonResponseInputStream;
    }

    public FindingParser parse() {
        final ArrayList<Finding> findings = new ArrayList<>();
        final JsonReader reader = Json.createReader(jsonResponseInputStream);
        final JsonArray jsonArray = reader.readArray();
        for (int i = 0; i < jsonArray.size(); i++) {
            final Finding finding = parseFinding(jsonArray.getJsonObject(i));
            if (!finding.getAnalysis().isSuppressed()) {
                findings.add(finding);
            }
        }
        this.findings = findings;
        return this;
    }

    private Finding parseFinding(JsonObject json) {
        final Project project = parseProject(json.getJsonObject("project"));
        final Component component = parseComponent(json.getJsonObject("component"));
        final Vulnerability vulnerability = parseVulnerability(json.getJsonObject("vulnerability"));
        final Analysis analysis = parseAnalysis(json.getJsonObject("analysis"));
        final String matrix = trimToNull(json.getString("matrix"));
        return new Finding(project, component, vulnerability, analysis, matrix);
    }

    /*
    Project was not included in the response in Dependency-Track v3.3.x, therefore make it optional.
     */
    private Project parseProject(JsonObject json) {
        if (json == null) {
            return null;
        }
        final String uuid = trimToNull(json.getString("uuid", null));
        final String name = trimToNull(json.getString("name", null));
        final String version = trimToNull(json.getString("version", null));
        return new Project(uuid, name, version);
    }

    private Component parseComponent(JsonObject json) {
        final String uuid = trimToNull(json.getString("uuid"));
        final String name = trimToNull(json.getString("name"));
        final String group = trimToNull(json.getString("group", null));
        final String version = trimToNull(json.getString("version", null));
        final String purl = trimToNull(json.getString("purl", null));
        return new Component(uuid, name, group, version, purl);
    }

    private Vulnerability parseVulnerability(JsonObject json) {
        final String uuid = trimToNull(json.getString("uuid"));
        final String source = trimToNull(json.getString("source"));
        final String vulnId = trimToNull(json.getString("vulnId", null));
        final String title = trimToNull(json.getString("title", null));
        final String subtitle = trimToNull(json.getString("subtitle", null));
        final String description = trimToNull(json.getString("description", null));
        final String recommendation = trimToNull(json.getString("recommendation", null));
        final Severity severity = Severity.valueOf(json.getString("severity", null));
        final Integer severityRank = json.getInt("severityRank", -1);
        final Integer cweId = json.getInt("cweId", -1);
        final String cweName = trimToNull(json.getString("cweName", null));
        return new Vulnerability(uuid, source, vulnId, title, subtitle, description, recommendation, severity, severityRank, cweId, cweName);
    }

    private Analysis parseAnalysis(JsonObject json) {
        final String state = trimToNull(json.getString("state", null));
        final boolean isSuppressed = json.getBoolean("isSuppressed", false);
        return new Analysis(state, isSuppressed);
    }

    public ArrayList<Finding> getFindings() {
        return findings;
    }

    private static String trimToNull(final String string) {
        if (string == null) {
            return null;
        }
        final String trimmed = string.trim();
        return trimmed.length() == 0 ? null : trimmed;
    }
}
