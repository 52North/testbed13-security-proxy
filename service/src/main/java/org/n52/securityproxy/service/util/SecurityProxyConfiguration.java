/*
 * Copyright 2017-2017 52°North Initiative for Geospatial Open Source
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
package org.n52.securityproxy.service.util;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.n52.securityproxy.service.util.Constants.ServiceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * configuration read from config.json in WEB-INF/conf
 *
 * @author staschc
 *
 */
public class SecurityProxyConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityProxyConfiguration.class);

    private String authorizationServer;

    private ServiceType serviceType;

    private String backendServiceURL;

    private String securityProxyURL;

    private static SecurityProxyConfiguration instance;

    private boolean oauthEnabled;

    private boolean authorizeDescribeProcess;

    private boolean authorizeDescribeProcessID;

    private boolean authorizeExecute;

    private boolean authorizeExecuteProcessID;

    private boolean authorizeInsertProcess;

    private boolean authorizeGetFeature;

    private boolean authorizeDescribeFeatureType;

    private boolean certificateEnabled;

    private List<String> processIdentifiers;

    private List<String> typeNames;

    private boolean authorizeGetFeatureTypeName;

    private boolean authorizeDescribeFeatureTypeName;

    private boolean authorizeTransaction;

    private SecurityProxyConfiguration(InputStream configJSON) {
        parseConfig(configJSON);
    }

    public static SecurityProxyConfiguration getInstance(InputStream configJSON) {
        if (instance != null) {
            return instance;
        } else {
            instance = new SecurityProxyConfiguration(configJSON);
            return instance;
        }

    }

    public static SecurityProxyConfiguration getInstance() {
        if (instance == null) {
            throw new RuntimeException("SecurityProxyConfiguration not initialized!");
        } else {
            return instance;
        }

    }

    public String getAuthorizationServer() {
        return authorizationServer;
    }

    public ServiceType getServiceType() {
        return serviceType;
    }

    public String getBackendServiceURL() {
        return backendServiceURL;
    }

    public boolean isOauthEnabled() {
        return oauthEnabled;
    }

    public boolean isCertificateEnabled() {
        return certificateEnabled;
    }

    public boolean isAuthorizeDescribeProcess() {
        return authorizeDescribeProcess;
    }

    public boolean isAuthorizeDescribeProcessID() {
        return authorizeDescribeProcessID;
    }

    public boolean isAuthorizeExecute() {
        return authorizeExecute;
    }

    public boolean isAuthorizeExecuteProcessID() {
        return authorizeExecuteProcessID;
    }

    public boolean isAuthorizeGetFeature() {
        return authorizeGetFeature;
    }

    public boolean isAuthorizeDescribeFeatureType() {
        return authorizeDescribeFeatureType;
    }

    private void parseConfig(InputStream configJSON) {
        ObjectMapper m = new ObjectMapper();
        try {
            JsonNode root = m.readTree(configJSON);
            authorizationServer = root.findPath("authorizationServer").asText();
            serviceType = ServiceType.valueOf(root.findPath("serviceType").asText());
            backendServiceURL = root.findPath("backendServiceURL").asText();
            securityProxyURL = root.findPath("securityProxyURL").asText();
            oauthEnabled = root.findPath("OAuthEnabled").asBoolean();
            certificateEnabled = root.findPath("certificateEnabled").asBoolean();

            authorizeDescribeProcess = root.findPath("authorizeDescribeProcess").asBoolean();
            authorizeDescribeProcessID = root.findPath("authorizeDescribeProcessIdentifier").asBoolean();

            authorizeExecute = root.findPath("authorizeExecute").asBoolean();
            authorizeExecuteProcessID = root.findPath("authorizeExecuteProcessIdentifier").asBoolean();

            authorizeInsertProcess = root.findPath("authorizeInsertProcess").asBoolean();

            authorizeGetFeature = root.findPath("authorizeGetFeature").asBoolean();
            authorizeGetFeatureTypeName = root.findPath("authorizeGetFeatureTypeName").asBoolean();

            authorizeDescribeFeatureType = root.findPath("authorizeDescribeFeatureType").asBoolean();
            authorizeDescribeFeatureTypeName = root.findPath("authorizeDescribeFeatureTypeName").asBoolean();

            authorizeTransaction = root.findPath("authorizeTransaction").asBoolean();

            processIdentifiers = parseStringArray(root.findPath("processIdentifiers").elements());

            typeNames = parseStringArray(root.findPath("typeNames").elements());
        } catch (Exception e) {
            LOGGER.error("Error while reading SecurityProxyConfiguration!");
            throw new RuntimeException("Error while reading SecurityProxyConfiguration!");
        }
    }

    private List<String> parseStringArray(Iterator<JsonNode> elements) {
        List<String> strings = new ArrayList<String>();
        while (elements.hasNext()) {
            strings.add(elements.next().asText());
        }
        return strings;

    }

    public String getSecurityProxyURL() {
        return securityProxyURL;
    }

    public List<String> getProcessIdentifiers() {
        return processIdentifiers;
    }

    public List<String> getTypeNames() {
        return typeNames;
    }

    public boolean isAuthorizeGetFeatureTypeName() {
        return authorizeGetFeatureTypeName;
    }

    public boolean isAuthorizeDescribeFeatureTypeName() {
        return authorizeDescribeFeatureTypeName;
    }

    public boolean isAuthorizeTransaction() {
        return authorizeTransaction;
    }

    public String replaceServiceURLs(String responseString) {
        String backendURL = this.getBackendServiceURL();

        if(responseString.contains("RetrieveResultServlet")){
            backendURL = this.getBackendServiceURL().replace("WebProcessingService", "RetrieveResultServlet");
            responseString = responseString.replaceAll(backendURL + "\\?", this.getSecurityProxyURL() + "?request=GetOutput&amp;version=2.0.0&amp;service=WPS&amp;");
        }else{
            responseString = responseString.replaceAll(backendURL, this.getSecurityProxyURL());
        }
        // quick workaround for chaging version in URL to feature schema
        responseString = responseString.replaceAll("&amp;version=2.0.2&amp;", "&amp;version=2.0.0&amp;");
        return responseString;
    }

    public boolean isAuthorizeInsertProcess() {
        return authorizeInsertProcess;
    }
}
