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
package org.n52.securityproxy.service.handler;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xmlbeans.XmlObject;
import org.n52.securityproxy.model.SimplePermission;
import org.n52.securityproxy.service.util.Constants.RequestType;
import org.n52.securityproxy.service.util.Constants.ServiceType;
import org.n52.securityproxy.service.util.HttpUtil;
import org.n52.securityproxy.service.util.OAuthUtil;
import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

import com.auth0.jwt.exceptions.TokenExpiredException;

import net.opengis.fes.x20.AbstractQueryExpressionType;
import net.opengis.ows.x20.CodeType;
import net.opengis.wfs.x20.DescribeFeatureTypeDocument;
import net.opengis.wfs.x20.GetFeatureDocument;
import net.opengis.wfs.x20.QueryType;
import net.opengis.wfs.x20.TransactionDocument;
import net.opengis.wps.x20.DescribeProcessDocument;
import net.opengis.wps.x20.ExecuteDocument;
import net.opengis.wps.x20.GetResultDocument;
import net.opengis.wps.x20.GetStatusDocument;
import net.opengis.wps.x20.InsertProcessDocument;

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
     * @throws IOException
     *             if parsing configuration fails
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
        if(token != null){
            token = token.replace("Bearer ", "");
            LOGGER.debug("Got token.");
        }
        List<String> scopes = null;
        String requestParam = HttpUtil.getParameterValue(req, "request");
        ResponseEntity<String> response = null;

        if (config.getServiceType() == ServiceType.wps) {
            // Execute operation
            if (requestParam.equals(RequestType.Execute.toString())) {

                // needs authorization
                if (config.isAuthorizeExecute()) {

                    String processID = HttpUtil.getParameterValue(req, "identifier");
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (checkExecuteScopes(scopes, processID, res)) {
                        response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(), ServiceType.wps);
                    }
                }

                // no authorization
                else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wps);
                }
            }

            // DescribeProcess
            else if (requestParam.equalsIgnoreCase(RequestType.DescribeProcess.toString())) {
                // needs authorization
                if (config.isAuthorizeDescribeProcess()) {
                    String processID = HttpUtil.getParameterValue(req, "identifier");

                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (checkDescribeProcessScopes(scopes, processID, res)) {
                        response =
                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                        ServiceType.wps);
                    }
                }

                // no authorization
                else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wps);
                }
            }

            // GetStatus
            else if (requestParam.equalsIgnoreCase(RequestType.GetStatus.toString())) {
                // needs authorization TODO implement
//                if (config.isAuthorizeGetStatus()) {
//                    String processID = HttpUtil.getParameterValue(req, "identifier");
//
//                    scopes = checkToken(token, res, publicKey);
//                    if (scopes == null) {
//                        return;
//                    }
//                    if (checkDescribeProcessScopes(scopes, processID, res)) {
//                        response =
//                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
//                                        ServiceType.wps);
//                    }
//                }

                // no authorization
//                else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wps);
//                }
            }

            // GetResult
            else if (requestParam.equalsIgnoreCase(RequestType.GetResult.toString())) {
                // needs authorization TODO implement
//                if (config.isAuthorizeGetResult()) {
//                    String processID = HttpUtil.getParameterValue(req, "identifier");
//
//                    scopes = checkToken(token, res, publicKey);
//                    if (scopes == null) {
//                        return;
//                    }
//                    if (checkDescribeProcessScopes(scopes, processID, res)) {
//                        response =
//                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
//                                        ServiceType.wps);
//                    }
//                }

                // no authorization
//                else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wps);
//                }
            }

            // GetOutput
            else if (requestParam.equalsIgnoreCase(RequestType.GetOutput.toString())) {
                // needs authorization TODO implement
//                if (config.isAuthorizeGetResult()) {
//                    String processID = HttpUtil.getParameterValue(req, "identifier");
//
//                    scopes = checkToken(token, res, publicKey);
//                    if (scopes == null) {
//                        return;
//                    }
//                    if (checkDescribeProcessScopes(scopes, processID, res)) {
//                        response =
//                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
//                                        ServiceType.wps);
//                    }
//                }

                // no authorization
//                else {

                String id = HttpUtil.getParameterValue(req, "id");

                String backendURL = config.getBackendServiceURL().replace("WebProcessingService", "RetrieveResultServlet");

                    response =
                            HttpUtil.httpGet(backendURL + "?" + "id=" + id,
                                    ServiceType.wps);
//                }
            }
        }

        else if (config.getServiceType() == ServiceType.wfs) {
            String typeName = HttpUtil.getParameterValue(req, "typeName");
            List<String> typeNames = new ArrayList<String>();
            typeNames.add(typeName);

            // GetFeature operation
            if (requestParam.equals(RequestType.GetFeature.toString())) {
                if (config.isAuthorizeGetFeature()) {
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (checkGetFeatureScopes(scopes, typeNames, res)) {
                        response =
                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                        ServiceType.wfs);

                    }
                } else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wfs);
                }
            }

            // DescribeFeatureType operation
            else if (requestParam.equals(RequestType.DescribeFeatureType.toString())) {
                if (config.isAuthorizeDescribeFeatureType()) {
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (checkDescribeFeatureTypeScopes(scopes, typeNames, res)) {
                        response =
                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                        ServiceType.wfs);
                    }
                } else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wfs);
                }
            }

            // Transaction operation
            else if (requestParam.equals(RequestType.Transaction.toString())) {
                if (config.isAuthorizeDescribeFeatureType()) {
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (checkTransactionScopes(scopes, typeNames, res)) {
                        response =
                                HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                        ServiceType.wfs);
                    }
                }

                // any other operation
                else {
                    response =
                            HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString(),
                                    ServiceType.wfs);
                }
            }

        }

        if (response != null) {
            handleOperationResponse(response, res);
        }
        return;

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
     *            request XML bean
     * @param simplePermission
     * @throws IOException
     *             if reading token or XML request fails
     *
     */
    public void post(HttpServletRequest req,
            HttpServletResponse res,
            InputStream publicKey,
            XmlObject postRequest, SimplePermission simplePermission) throws IOException {
        String token = req.getHeader("Authorization");
        if(token != null){
            LOGGER.debug("Got token.");
            token = token.replace("Bearer ", "");
        }
        List<String> scopes = null;
        ResponseEntity<String> response = null;

        // WPS
        if (config.getServiceType() == ServiceType.wps) {

            // Execute operation
            if (postRequest instanceof ExecuteDocument) {
                if (config.isAuthorizeExecute()) {

                    boolean isUserAuthentication = config.isUserAuthentication();

                    if (isUserAuthentication) {

                        // check access token against userInfoEndpoint
                        if(checkAccessToken(token, simplePermission, res)){
                            response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                        }
                    } else {

                        String processID = ((ExecuteDocument) postRequest).getExecute().getIdentifier().getStringValue();
                        scopes = checkToken(token, res, publicKey);
                        if (scopes == null) {
                            return;
                        }

                        // check scopes and execute, if authorized
                        if (checkExecuteScopes(scopes, processID, res)) {
                            response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                        }
                    }
                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // DescribeProcess
            else if (postRequest instanceof DescribeProcessDocument) {

                if (config.isAuthorizeDescribeProcess()) {
                    // TODO currently only single processIdentifier supported!
                    String processID = null;
                    CodeType[] processIDArray =
                            ((DescribeProcessDocument) postRequest).getDescribeProcess().getIdentifierArray();
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }
                    if (processIDArray.length == 1) {
                        processID = processIDArray[0].getStringValue();
                    } else {
                        throw new RuntimeException(
                                "Currently only one identifier supported for DescribeProcess operation!");
                    }

                    // check scopes and execute, if authorized
                    if (checkDescribeProcessScopes(scopes, processID, res)) {
                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                    }
                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // GetStatus
            else if (postRequest instanceof GetStatusDocument) {

//                if (config.isAuthorizeGetStatus()) {//TODO implement
//                    // TODO currently only single processIdentifier supported!
//                    String processID = null;
//                    CodeType[] processIDArray =
//                            ((DescribeProcessDocument) postRequest).getDescribeProcess().getIdentifierArray();
//                    scopes = checkToken(token, res, publicKey);
//                    if (scopes == null) {
//                        return;
//                    }
//                    if (processIDArray.length == 1) {
//                        processID = processIDArray[0].getStringValue();
//                    } else {
//                        throw new RuntimeException(
//                                "Currently only one identifier supported for DescribeProcess operation!");
//                    }
//
//                    // check scopes and execute, if authorized
//                    if (checkDescribeProcessScopes(scopes, processID, res)) {
//                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
//                    }
//                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
//                }
            }

            // GetResult
            else if (postRequest instanceof GetResultDocument) {

//                if (config.isAuthorizeGetResult()) {//TODO implement
//                    // TODO currently only single processIdentifier supported!
//                    String processID = null;
//                    CodeType[] processIDArray =
//                            ((DescribeProcessDocument) postRequest).getDescribeProcess().getIdentifierArray();
//                    scopes = checkToken(token, res, publicKey);
//                    if (scopes == null) {
//                        return;
//                    }
//                    if (processIDArray.length == 1) {
//                        processID = processIDArray[0].getStringValue();
//                    } else {
//                        throw new RuntimeException(
//                                "Currently only one identifier supported for DescribeProcess operation!");
//                    }
//
//                    // check scopes and execute, if authorized
//                    if (checkDescribeProcessScopes(scopes, processID, res)) {
//                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
//                    }
//                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
//                }
            }

            // InsertProcess
            else if (postRequest instanceof InsertProcessDocument) {

                if (config.isAuthorizeInsertProcess()) {

                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }

                    // check scopes and execute, if authorized
                    if (checkInsertProcessScope(scopes, res)) {
                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                    }
                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }
        }

        // WFS
        else if (config.getServiceType() == ServiceType.wfs) {

            // GetFeature operation
            if (postRequest instanceof GetFeatureDocument) {

                if (config.isAuthorizeGetFeature()) {

                    // extract typeNames
                    List<String> typeNames = new ArrayList<String>();
                    AbstractQueryExpressionType[] queries =
                            ((GetFeatureDocument) postRequest).getGetFeature().getAbstractQueryExpressionArray();
                    for (AbstractQueryExpressionType query : queries) {
                        QueryType expr = (QueryType) query;
                        Iterator<?> featureTypes = expr.getTypeNames().iterator();
                        while (featureTypes.hasNext()) {
                            String typeName = (String) featureTypes.next();
                            typeNames.add(typeName);
                        }

                    }

                    // check token
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }

                    // check scopes and execute, if authorized
                    if (checkGetFeatureScopes(scopes, typeNames, res)) {
                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                    }
                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // DescribeFeatureType operation
            else if (postRequest instanceof DescribeFeatureTypeDocument) {
                if (config.isAuthorizeDescribeFeatureType()) {
                    List<String> typeNames = new ArrayList<String>();
                    AbstractQueryExpressionType[] queries =
                            ((GetFeatureDocument) postRequest).getGetFeature().getAbstractQueryExpressionArray();
                    for (AbstractQueryExpressionType query : queries) {
                        QueryType expr = (QueryType) query;
                        Iterator<?> featureTypes = expr.getTypeNames().iterator();
                        while (featureTypes.hasNext()) {
                            String typeName = (String) featureTypes.next();
                            typeNames.add(typeName);
                        }

                    }

                    // check token
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }

                    // check scopes and execute, if authorized
                    if (checkDescribeFeatureTypeScopes(scopes, typeNames, res)) {
                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                    }
                } else {
                    response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                }
            }

            // Transaction operation
            else if (postRequest instanceof TransactionDocument) {
                if (config.isAuthorizeTransaction()) {
                    List<String> typeNames = new ArrayList<String>();
                    AbstractQueryExpressionType[] queries =
                            ((GetFeatureDocument) postRequest).getGetFeature().getAbstractQueryExpressionArray();
                    for (AbstractQueryExpressionType query : queries) {
                        QueryType expr = (QueryType) query;
                        Iterator<?> featureTypes = expr.getTypeNames().iterator();
                        while (featureTypes.hasNext()) {
                            String typeName = (String) featureTypes.next();
                            typeNames.add(typeName);
                        }

                    }

                    // check token
                    scopes = checkToken(token, res, publicKey);
                    if (scopes == null) {
                        return;
                    }

                    // check scopes and execute, if authorized
                    if (checkTransactionScopes(scopes, typeNames, res)) {
                        response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
                    }
                }
            }

            //any other operation
            else {
                response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
            }

        }

        if (response != null) {
            handleOperationResponse(response, res);
        }
        return;

    }

    private void handleOperationResponse(ResponseEntity<String> resp,
            HttpServletResponse res) throws IOException {
        HttpUtil.setHeaders(res, resp);
        String response = config.replaceServiceURLs(resp.getBody());
        Writer writer = res.getWriter();
        writer.write(response);

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

    private boolean checkInsertProcessScope(List<String> scopes, HttpServletResponse res) throws IOException {
        if (!scopes.contains("Execute")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for InsertProcess operation.");
            return false;
        }
        return true;
    }

    private boolean checkDescribeProcessScopes(List<String> scopes,
            String processID,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("DescribeProcess")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for DescribeProcess operation.");
            return false;
        }
        if (config.isAuthorizeDescribeProcessID()) {

            if (!scopes.contains("DescribeProcess/ProcessID=" + processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for DescribeProcess operation.");
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

                if (!scopes.contains("GetFeature/TypeName=" + typeName)) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    res.getWriter().write("No valid scope for GetFeature operation with type name: " + typeName + ".");
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkTransactionScopes(List<String> scopes,
            List<String> typeNames,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("Transaction")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for Transaction operation.");
            return false;
        }

        return true;
    }

    private List<String> checkToken(String token,
            HttpServletResponse res,
            InputStream publicKey) throws IOException {
        if (token == null) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.getWriter().write("OAuth access token is needed to request this service operation.");
            return null;
        } else {
            List<String> scopes;
            try {
                scopes = OAuthUtil.getScopesFromToken(publicKey, token, "https://bpross-52n.eu.auth0.com/");
            } catch (TokenExpiredException e) {
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                res.getWriter().write(e.getMessage());
                return null;
            } catch (GeneralSecurityException | IOException e) {
                LOGGER.error("Error while validating and parsing token", e);
                throw new RuntimeException("Error while validating and parsing token", e);
            }

            return scopes;
        }
    }

    private boolean checkAccessToken(String token, SimplePermission simplePermission,
            HttpServletResponse res) throws IOException {

        String userName = OAuthUtil.getUserNameFromAccessToken(token);

        if(!simplePermission.getSubjects().contains(userName)){
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("User doesn't have access to requested resource or operation.");
            return false;
        }

        return true;

    }

}
