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
package org.dependencytrack.integrations.fortifyssc.model;

public class Finding {

    private final Project project;
    private final Component component;
    private final Vulnerability vulnerability;
    private final Analysis analysis;
    private final String matrix;

    public Finding(Project project, Component component, Vulnerability vulnerability, Analysis analysis, String matrix) {
        this.project = project;
        this.component = component;
        this.vulnerability = vulnerability;
        this.analysis = analysis;
        this.matrix = matrix;
    }

    public Project getProject() {
        return project;
    }

    public Component getComponent() {
        return component;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public Analysis getAnalysis() {
        return analysis;
    }

    public String getMatrix() {
        return matrix;
    }
}
