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
package org.n52.securityproxy.service.handler;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.opengis.fes.x20.AbstractQueryExpressionType;
import net.opengis.ows.x20.CodeType;
import net.opengis.wfs.x20.DescribeFeatureTypeDocument;
import net.opengis.wfs.x20.GetFeatureDocument;
import net.opengis.wfs.x20.QueryType;
import net.opengis.wps.x20.DescribeProcessDocument;
import net.opengis.wps.x20.ExecuteDocument;

import org.apache.xmlbeans.XmlObject;
import org.n52.securityproxy.service.util.Constants.RequestType;
import org.n52.securityproxy.service.util.Constants.ServiceType;
import org.n52.securityproxy.service.util.HttpUtil;
import org.n52.securityproxy.service.util.OAuthUtil;
import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

/**
 * handler for maning request to OAuth secured OGC Web Services. Currently
 * supports
 *
 *
 * @author staschc
 */
public class OAuthHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuthHandler.class);

    private SecurityProxyConfiguration config;

    /**
     * constructor
     *
     */
    public OAuthHandler() throws IOException {
        config = SecurityProxyConfiguration.getInstance();

    }

    /**
     * verifies token, checks scopes, and, if authorized, forwards GET request
     * to secured OGC service
     *
     * @param req
     *            request to service
     * @param res
     *            response that should be sent to client
     * @param publicKey
     *            stream to public key that is needed for token verification
     * @throws IOException
     *             if response encoding fails
     *
     */
    public void get(HttpServletRequest req,
            HttpServletResponse res,
            InputStream publicKey) throws IOException {
        String token = req.getHeader("Authorization");
        List<String> scopes = new ArrayList<>();
        String requestParam = req.getParameter("request");
        ResponseEntity<String> response = null;
        if (token == null) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        try {
            scopes = OAuthUtil.getScopesFromToken(publicKey, token, "https://bpross-52n.eu.auth0.com/");
        } catch (GeneralSecurityException | IOException e) {
            LOGGER.error("Error while validating and parsing token", e);
            throw new RuntimeException("Error while validating and parsing token", e);
        }

        if (config.getServiceType() == ServiceType.wps) {
            // Execute operation
            if (requestParam.equals(RequestType.Execute.toString()) && config.isAuthorizeExecute()) {
                String processID = req.getParameter("identifier");
                if (checkExecuteScopes(scopes, processID, res)) {
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            // DescribeProcess
            else if (requestParam.equalsIgnoreCase(RequestType.DescribeProcess.toString())
                    && config.isAuthorizeDescribeProcess()) {
                String processID = req.getParameter("identifier");
                if (checkDescribeProcessScopes(scopes, processID, res)) {
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }
        }

        else if (config.getServiceType() == ServiceType.wfs) {
            String typeName = req.getParameter("typeName");
            List<String> typeNames = new ArrayList<String>();
            typeNames.add(typeName);

            // GetFeature operation
            if (requestParam.equals(RequestType.GetFeature.toString()) && config.isAuthorizeGetFeature()) {
                if (checkGetFeatureScopes(scopes, typeNames, res)) {
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            if (requestParam.equals(RequestType.DescribeFeatureType.toString())
                    && config.isAuthorizeDescribeFeatureType()) {
                if (checkDescribeFeatureTypeScopes(scopes, typeNames, res)) {
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

        }

        if (response != null) {
            handleOperationResponse(response, res);
        }

    }

    /**
     * verifies token, checks scopes, and, if authorized, forwards POST request
     * to secured OGC service
     *
     * @param req
     *            request to service
     * @param res
     *            response that should be sent to client
     * @param publicKey
     *            stream to public key that is needed for token verification
     * @param postRequest
     * @throws IOException
     *
     */
    public void post(HttpServletRequest req,
            HttpServletResponse res,
            InputStream publicKey,
            XmlObject postRequest) throws IOException {
        String token = req.getHeader("Authorization");
        List<String> scopes = new ArrayList<>();
        ResponseEntity<String> response = null;

        // check token first
        if (token == null) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // extract scopes
        try {
            scopes = OAuthUtil.getScopesFromToken(publicKey, token, "https://bpross-52n.eu.auth0.com/");
        } catch (IOException e) {
            LOGGER.error("Error while validating and parsing token", e);
            throw new RuntimeException("Error while validating and parsing token", e);
        } catch (GeneralSecurityException ge) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.getWriter().write(ge.getMessage());
            return;
        }

        // WPS
        if (config.getServiceType() == ServiceType.wps) {

            // Execute operation
            if (postRequest instanceof ExecuteDocument && config.isAuthorizeExecute()) {
                String processID = ((ExecuteDocument) postRequest).getExecute().getIdentifier().getStringValue();
                if (checkExecuteScopes(scopes, processID, res)) {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // DescribeProcess
            else if (postRequest instanceof DescribeProcessDocument && config.isAuthorizeDescribeProcess()) {
                // TODO currently only single processIdentifier supported!
                String processID = null;
                CodeType[] processIDArray =
                        ((DescribeProcessDocument) postRequest).getDescribeProcess().getIdentifierArray();
                if (processIDArray.length == 1) {
                    processID = processIDArray[0].getStringValue();
                } else {
                    throw new RuntimeException("Currently only one identifier supported for DescribeProcess operation!");
                }

                if (checkDescribeProcessScopes(scopes, processID, res)) {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }
        }

        // WFS
        else if (config.getServiceType() == ServiceType.wfs) {

            // GetFeature operation
            if (postRequest instanceof GetFeatureDocument && config.isAuthorizeGetFeature()) {
                List<String> typeNames = new ArrayList<String>();
                AbstractQueryExpressionType[] queries =
                        ((GetFeatureDocument) postRequest).getGetFeature().getAbstractQueryExpressionArray();
                for (AbstractQueryExpressionType query : queries) {
                    QueryType expr = (QueryType) query;
                    Iterator featureTypes = expr.getTypeNames().iterator();
                    while (featureTypes.hasNext()) {
                        String typeName = (String) featureTypes.next();
                        typeNames.add(typeName);
                    }

                }
                if (checkGetFeatureScopes(scopes, typeNames, res)) {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // DescribeFeatureType operation
            else if (postRequest instanceof DescribeFeatureTypeDocument && config.isAuthorizeDescribeFeatureType()) {
                List<String> typeNames = new ArrayList<String>();
                AbstractQueryExpressionType[] queries =
                        ((GetFeatureDocument) postRequest).getGetFeature().getAbstractQueryExpressionArray();
                for (AbstractQueryExpressionType query : queries) {
                    QueryType expr = (QueryType) query;
                    Iterator featureTypes = expr.getTypeNames().iterator();
                    while (featureTypes.hasNext()) {
                        String typeName = (String) featureTypes.next();
                        typeNames.add(typeName);
                    }

                }
                if (checkDescribeFeatureTypeScopes(scopes, typeNames, res)) {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

        }

        if (response != null) {
            handleOperationResponse(response, res);
        }

    }

    private void handleOperationResponse(ResponseEntity<String> resp,
            HttpServletResponse res) throws IOException {
        HttpUtil.setHeaders(res, resp);
        res.getWriter().write(resp.getBody());
    }

    private boolean checkExecuteScopes(List<String> scopes,
            String processID,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("Execute")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for Execute operation.");
            return false;
        }
        if (config.isAuthorizeExecuteProcessID()) {

            // check whether identifier is in identifier that are offered as
            // protected resources
            if (!config.getProcessIdentifiers().contains(processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for Execute operation.");
                return false;
            }

            // check whether corresponding scope is passed
            if (!scopes.contains("Execute/ProcessID=" + processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for Execute operation.");
                return false;
            }
        }
        return true;
    }

    private boolean checkDescribeProcessScopes(List<String> scopes,
            String processID,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("DescribeProcess")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for Execute operation.");
            return false;
        }
        if (config.isAuthorizeDescribeProcessID()) {

            if (!scopes.contains("DescribeProcess/ProcessID=" + processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for Execute operation.");
                return false;
            }
        }
        return true;
    }

    private boolean checkDescribeFeatureTypeScopes(List<String> scopes,
            List<String> typeNames,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("DescribeFeatureType")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for DescribeFeatureType operation.");
            return false;
        }
        if (config.isAuthorizeDescribeFeatureTypeName()) {

            // check whether corresponding scopes for type names are passed
            for (String typeName : typeNames) {
                if (!config.getTypeNames().contains(typeName)) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write("No valid scope for DescribeFeatureTypeName operation.");
                    return false;
                }

                // check whether corresponding scope is passed
                if (!scopes.contains("DescribeFeatureType/TypeName=" + typeName)) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write(
                            "No valid scope for DescribeFeatureType operation with type name: " + typeName + ".");
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkGetFeatureScopes(List<String> scopes,
            List<String> typeNames,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("GetFeature")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for GetFeature operation.");
            return false;
        }
        if (config.isAuthorizeGetFeatureTypeName()) {
            // check whether corresponding scopes for type names are passed
            for (String typeName : typeNames) {
                // check whether identifier is in identifier that are offered as
                // protected resources
                if (!config.getTypeNames().contains(typeName)) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write("No valid scope for GetFeature operation.");
                    return false;
                }

                if (!scopes.contains("GetFeatureType/TypeName=" + typeName)) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write("No valid scope for GetFeature operation with type name: " + typeName + ".");
                    return false;
                }
            }
        }
        return true;
    }

}
