/*
 * Copyright 2017-2018 52°North Initiative for Geospatial Open Source
 * Software GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.n52.securityproxy.model;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class SimplePermission {

    private Set<String> resources;

    private Set<String> actions;

    private Set<String> subjects;

    private String name;

    public SimplePermission(){
        resources = new HashSet<>();
        actions = new HashSet<>();
        subjects = new HashSet<>();
    }

    public Set<String> getResources() {
        return resources;
    }

    public Set<String> getActions() {
        return actions;
    }

    public Set<String> getSubjects() {
        return subjects;
    }

    public void addResource(String resource){
        resources.add(resource);
    }

    public void addAction(String action){
        actions.add(action);
    }

    public void addSubject(String subject){
        subjects.add(subject);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {

        String lineSeparator = System.getProperty("line.separator");

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Name: " + name + lineSeparator);
        stringBuilder.append("Resources: " + resources.stream().collect(Collectors.joining(", ")) + lineSeparator);
        stringBuilder.append("Actions: " + actions.stream().collect(Collectors.joining(", ")) + lineSeparator);
        stringBuilder.append("Subjects: " + subjects.stream().collect(Collectors.joining(", ")) + lineSeparator);

        return stringBuilder.toString();
    }

}
