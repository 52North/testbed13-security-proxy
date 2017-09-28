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

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.n52.securityproxy.service.util.Base64CertDecoder;
import org.n52.securityproxy.service.util.HttpUtil;
import org.n52.securityproxy.service.util.SOAPMessageHelper;
import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;

/**
 *
 * @author staschc
 */
public class X509Handler {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509Handler.class);

    private X509Certificate cert;

    private String principalName;

    private String request;

    private String toURL;

    // public void get(HttpServletRequest req,
    // HttpServletResponse res) {
    // readCertificate(req);
    // }

    public void post(HttpServletRequest req,
            HttpServletResponse res, XmlObject postRequest) {
        try {
            readCertificate(postRequest);
            //TODO validate!?
            if(!checkAccessControlList()){
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            ResponseEntity<String> response = forwardRequest();

            HttpUtil.setHeaders(res, response);

            String content = response.getBody();

            BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(res.getOutputStream()));

            bufferedWriter.write(content);

            bufferedWriter.close();

        } catch (Exception e) {
            res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            //TODO write reason
            return;
        }
    }

    private ResponseEntity<String> forwardRequest() throws XmlException {

        XmlObject requestObject = XmlObject.Factory.parse(request);

        ResponseEntity<String> response = HttpUtil.httpPost(SecurityProxyConfiguration.getInstance().getBackendServiceURL(), requestObject);

        return response;
    }

    private boolean checkAccessControlList() {
        LOGGER.debug(principalName);

        return true;
    }

    private void readCertificate(XmlObject postRequest) {

        try {
            SOAPMessageHelper soapMessageHelper = new SOAPMessageHelper().getToAndCertificateFromSOAPRequest(postRequest.newInputStream());

            request = soapMessageHelper.getRequest();

            toURL = soapMessageHelper.getToURL();

            Base64CertDecoder base64CertDecoder = new Base64CertDecoder().decodeBase64EndodedCertificateString(soapMessageHelper.getBase64EncodedCertificate());

            cert = base64CertDecoder.getCertificate();

            principalName = base64CertDecoder.getPrincipalCN();

        } catch (Exception e) {
            LOGGER.error("Could not parse SOAP request.", e);
        }
    }

    public void get(HttpServletRequest req,
            HttpServletResponse res) {

        String sslcert = req.getHeader("X-SSL-CERT");

        if(sslcert == null){
            res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            try {
                res.getWriter().write("Could not fetch certificate from header: " + "X-SSL-CERT");
            } catch (IOException e) {
                // ignore
            }
        }

        String lineSeperator = System.getProperty("line.separator");

        sslcert = sslcert.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----" + lineSeperator);
        sslcert = sslcert.replace("-----END CERTIFICATE-----", lineSeperator + "-----END CERTIFICATE-----");

        Base64CertDecoder base64CertDecoder;
        try {
            base64CertDecoder = new Base64CertDecoder().decodeBase64EndodedClientCertificateString(sslcert);

            cert = base64CertDecoder.getCertificate();

            principalName = base64CertDecoder.getPrincipalCN();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | javax.security.cert.CertificateException | IOException e) {

            res.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            try {
                res.getWriter().write("Could not decode certificate: " + sslcert);
            } catch (IOException e2) {
                // ignore
            }
        }


    }
}
