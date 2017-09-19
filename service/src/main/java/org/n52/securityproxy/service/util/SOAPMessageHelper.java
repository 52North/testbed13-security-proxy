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

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SOAPMessageHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(SOAPMessageHelper.class);

    private String toURL;

    private String base64EncodedCertificate;

    private String request;

    public SOAPMessageHelper() {
    }

    public SOAPMessageHelper getToAndCertificateFromSOAPRequest(InputStream in) throws IOException, SOAPException, XPathExpressionException, ParserConfigurationException, SAXException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(in));

        javax.xml.xpath.XPath xpath = XPathFactory.newInstance().newXPath();

        Node toNode = (Node) xpath.evaluate("//Envelope/Header/To/text()", doc.getDocumentElement(), XPathConstants.NODE);

        toURL = toNode.getTextContent();

        Node certNode = (Node) xpath.evaluate("//Envelope/Header/Security/BinarySecurityToken/text()", doc.getDocumentElement(), XPathConstants.NODE);

        base64EncodedCertificate = certNode.getTextContent();

        Node requestNode = (Node) xpath.evaluate("//Envelope/Body", doc.getDocumentElement(), XPathConstants.NODE);

        try {
            request = nodeToString(requestNode.getChildNodes().item(1));
        } catch (TransformerFactoryConfigurationError | TransformerException e) {
            LOGGER.error("Could not transform XML in SOAP body to String.", e);
        }

        return this;
    }

    public String nodeToString(Node node) throws TransformerFactoryConfigurationError, TransformerException {
        StringWriter stringWriter = new StringWriter();
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(new DOMSource(node), new StreamResult(stringWriter));

        return stringWriter.toString();
    }

    public String getToURL() {
        return toURL;
    }

    public String getBase64EncodedCertificate() {
        return base64EncodedCertificate;
    }

    public String getRequest() {
        return request;
    }

}
