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
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.n52.securityproxy.service.util.Constants.RequestType;
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
     *            if response encoding fails
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

        else {
            try {
                scopes = OAuthUtil.getScopesFromToken(publicKey, token, "https://bpross-52n.eu.auth0.com/");
            } catch (GeneralSecurityException | IOException e) {
                LOGGER.error("Error while validating and parsing token", e);
                throw new RuntimeException("Error while validating and parsing token", e);
            }

            // Execute operation
            if (requestParam.equals(RequestType.Execute.toString()) && config.isAuthorizeExecute()) {
                if (checkExecuteScopes(scopes, req, res)){
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            // DescribeProcess
            else if (requestParam.equalsIgnoreCase(RequestType.DescribeProcess.toString())
                    && config.isAuthorizeDescribeProcess()) {
                if (checkDescribeProcessScopes(scopes, req, res)){
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            // GetFeature operation
            if (requestParam.equals(RequestType.GetFeature.toString()) && config.isAuthorizeExecute()) {
                if (checkGetFeatureScopes(scopes, req, res)){
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            if (requestParam.equals(RequestType.DescribeFeatureType.toString()) && config.isAuthorizeExecute()) {
                if (checkDescribeFeatureTypeScopes(scopes, req, res)){
                    response = HttpUtil.httpGet(config.getBackendServiceURL() + "?" + req.getQueryString());
                }
            }

            if (response != null){
                handleOperationResponse(response, res);
            }
        }

    }

    private boolean checkDescribeFeatureTypeScopes(List<String> scopes,
            HttpServletRequest req,
            HttpServletResponse res) {
        // TODO Auto-generated method stub
        return true;
    }

    private boolean checkGetFeatureScopes(List<String> scopes,
            HttpServletRequest req,
            HttpServletResponse res) {
        // TODO Auto-generated method stub
        return true;
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
     *
     */
    public void post(HttpServletRequest req,
            HttpServletResponse res,
            InputStream publicKey) {
        String token = req.getHeader("Authorization");
        List<String> scopes = new ArrayList<>();

        if (token == null) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } else {
            try {
                scopes = OAuthUtil.getScopesFromToken(publicKey, token, "https://bpross-52n.eu.auth0.com/");
            } catch (GeneralSecurityException | IOException e) {
                LOGGER.error("Error while validating and parsing token", e);
                throw new RuntimeException("Error while validating and parsing token", e);
            }
        }

    }

    private void handleOperationResponse(ResponseEntity<String> resp,
            HttpServletResponse res) throws IOException {
        HttpUtil.setHeaders(res, resp);
        res.getWriter().write(resp.getBody());
        ;
    }

    private boolean checkExecuteScopes(List<String> scopes,
            HttpServletRequest req,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("Execute")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for Execute operation.");
            return false;
        }
        if (config.isAuthorizeExecuteProcessID()) {
            String processID = req.getParameter("identifier");
            if (!scopes.contains("Execute/ProcessID=" + processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for Execute operation.");
                return false;
            }
        }
        return true;
    }


    private boolean checkDescribeProcessScopes(List<String> scopes,
            HttpServletRequest req,
            HttpServletResponse res) throws IOException {
        if (!scopes.contains("DescribeProcess")) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("No valid scope for Execute operation.");
            return false;
        }
        if (config.isAuthorizeDescribeProcessID()) {
            String processID = req.getParameter("identifier");
            if (!scopes.contains("DescribeProcess/ProcessID=" + processID)) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.getWriter().write("No valid scope for Execute operation.");
                return false;
            }
        }
        return true;
    }

}
