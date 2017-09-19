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
package org.n52.securityproxy.service;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlOptions;
import org.n52.securityproxy.service.handler.AWSHandler;
import org.n52.securityproxy.service.handler.CapabilitiesInjector;
import org.n52.securityproxy.service.handler.OAuthHandler;
import org.n52.securityproxy.service.handler.X509Handler;
import org.n52.securityproxy.service.util.HttpUtil;
import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.n52.securityproxy.service.util.XMLBeansHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.ServletConfigAware;
import org.springframework.web.context.ServletContextAware;

import net.opengis.wfs.x20.WFSCapabilitiesDocument;
import net.opengis.wps.x20.CapabilitiesDocument;
import net.opengis.wps.x20.GetCapabilitiesDocument;

@Controller
@RequestMapping(
        value = "/service", consumes = "*/*", produces = "*/*")
public class Service implements ServletContextAware, ServletConfigAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(Service.class);

    private ServletContext ctx;

    private SecurityProxyConfiguration config;

    public void init() {
        config = SecurityProxyConfiguration.getInstance(ctx.getResourceAsStream("/WEB-INF/config/config.json"));
    }

    @RequestMapping(
            value = "{serviceId}", method = RequestMethod.GET)
    public void get(@PathVariable String serviceId,
            HttpServletRequest req,
            HttpServletResponse res) throws Exception {

        LOGGER.info("Incoming request for service with id: " + serviceId);

        // check, whether request is GetCapabilities
        String requestParam = HttpUtil.getParameterValue(req, "request");
        String queryString = req.getQueryString();
        String serviceParam = HttpUtil.getParameterValue(req, "service");

        // check whether service in URL is correct
        if (!serviceId.equalsIgnoreCase(config.getServiceType().toString())) {
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.getWriter().write("Endpoint is not available! Supported endpoint is:" + config.getBackendServiceURL());
            return;
        }

        // check service request param
        if (!serviceParam.equalsIgnoreCase(config.getServiceType().toString())) {
            res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            res.getWriter().write(
                    "Wrong service type! Service is " + config.getServiceType().toString() + ". Requested service is: "
                            + serviceParam);
            return;
        }

        if (serviceParam.equalsIgnoreCase("aws")){

            AWSHandler awsHandler = new AWSHandler();

            awsHandler.get(req, res);

            return;
        }

        if (requestParam.equals("GetCapabilities")) {

            if (serviceParam.equalsIgnoreCase("wfs")) {

                String version = HttpUtil.getParameterValue(req, "version");
                if (version == null) {
                    queryString = queryString.concat("&version=2.0.0");
                }
                if (version != null && !version.equals("2.0.0")) {
                // TODO maybe change to exception response
                    res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    res.getWriter().write("Service only supports version 2.0.0. Requested version was " + version + ".");
                    return;
                }
            }else if (serviceParam.equalsIgnoreCase("wps")) {

                String version = HttpUtil.getParameterValue(req, "acceptversions");
                if (version == null) {
                    queryString = queryString.concat("&acceptversions=2.0.0");
                }
                if (version != null && !version.equals("2.0.0")) {
                    res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    res.getWriter().write("Service only supports version 2.0.0. Requested version was " + version + ".");
                    return;
                }
            }
            ResponseEntity<String> response =
                    HttpUtil.httpGet(config.getBackendServiceURL() + "?" + queryString,
                            config.getServiceType());
            handleCapabilitiesResponse(response, res);
        }

        // other requests than GetCapabilities
        else {

//            String version = HttpUtil.getParameterValue(req, "version");
//            if (version == null) {
//                queryString = queryString.concat("&version=\"2.0.0\"");//TODO queryString is not used
//            }
//            if (version != null && !version.equals("2.0.0")) {
//                res.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//                res.getWriter().write("Service only supports version 2.0.0. Requested version was " + version + ".");
//                return;
//            }

            // if certificate enabled, extract certificate and pass request to
            // X509handler
            if (config.isCertificateEnabled()) {
//                X509Handler handler = new X509Handler();
                res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                res.getWriter().write("Require certificate sent in SOAP Header.");
            }

            // if OAuth enabled, check whether token is passed; if token is
            // missing, return
            if (config.isOauthEnabled()) {

                OAuthHandler handler = new OAuthHandler();
                handler.get(req, res, ctx.getResourceAsStream("/WEB-INF/pubkey/pubkey.pem"));
            }

        }

    }

    @RequestMapping(
            value = "{serviceId}", method = RequestMethod.POST)
    public void post(@PathVariable String serviceId,
            HttpServletRequest req,
            HttpServletResponse res) throws Exception {

        LOGGER.info("Incoming request for service with id: " + serviceId);

        XmlObject postRequest = XmlObject.Factory.parse(req.getInputStream());

        // GetCapabilities Request
        if (postRequest instanceof GetCapabilitiesDocument
                || postRequest instanceof net.opengis.wfs.x20.GetCapabilitiesDocument) {
            ResponseEntity<String> response = HttpUtil.httpPost(config.getBackendServiceURL(), postRequest);
            handleCapabilitiesResponse(response, res);
        }

        else {

            // if certificate enabled, extract certificate and pass request to
            // X509handler
            if (config.isCertificateEnabled()) {
                X509Handler handler = new X509Handler();
                handler.post(req, res, postRequest);
            }

            // if OAuth enabled, check whether token is passed; if token is
            // missing, return
            if (config.isOauthEnabled()) {

                OAuthHandler handler = new OAuthHandler();
                handler.post(req, res, ctx.getResourceAsStream("/WEB-INF/pubkey/pubkey.pem"), postRequest);
            }

        }

    }

    @Override
    public void setServletConfig(ServletConfig arg0) {
    }

    @Override
    public void setServletContext(ServletContext arg0) {
        this.ctx = arg0;
    }

    /**
     * helper for handling Capabilities response documents, injecting security
     * infos and forwarding them to clients
     *
     * @param capsResp
     *            response from Backendservice
     * @param res
     *            HttpServletResponse used to send response to client
     * @throws IOException
     *
     * @throws XmlException
     */
    private void handleCapabilitiesResponse(ResponseEntity<String> capsResp,
            HttpServletResponse res) throws IOException, XmlException {
        PrintWriter writer = res.getWriter();
        HttpUtil.setHeaders(res, capsResp);
        CapabilitiesInjector inj = new CapabilitiesInjector();
        XmlObject caps = XmlObject.Factory.parse(capsResp.getBody());
        XmlOptions xmlOpts = XMLBeansHelper.getWPSXmlOptions(); // TODO
                                                                // apparently no
                                                                // influence of
                                                                // xmlOpts so
                                                                // far...

        // WPS Capabilities
        if (caps instanceof CapabilitiesDocument) {
            inj.injectWPSCaps((CapabilitiesDocument) caps);
            String capsString = config.replaceServiceURLs(caps.xmlText(xmlOpts));
            writer.write(capsString);
        }

        // WFS Capabilities
        else if (caps instanceof WFSCapabilitiesDocument) {
            inj.injectWFSCaps((WFSCapabilitiesDocument) caps);
            String capsString = config.replaceServiceURLs(caps.xmlText(xmlOpts));
            writer.write(capsString);
        }
        // either exception or Capabilities of service which is not supported;
        // response is simply forwarded
        else {
            writer.write(capsResp.getBody());
        }
    }

}
