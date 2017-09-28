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
package org.n52.securityproxy.model;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class SimplePermissionsParser {

    private static Logger LOGGER = LoggerFactory.getLogger(SimplePermissionsParser.class);
    private DocumentBuilderFactory builderFactory;
    private DocumentBuilder builder;
    private XPath xPath;


    public SimplePermissionsParser() {
        builderFactory = DocumentBuilderFactory.newInstance();
        try {
            builder = builderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            LOGGER.error("Could not create new Document builder.", e);
        }

        xPath = XPathFactory.newInstance().newXPath();
    }


    public SimplePermission parse(InputStream in) throws ParserConfigurationException, SAXException, IOException {

        SimplePermission result = new SimplePermission();

        Document xmlDocument = builder.parse(in);

        String expression = "/SimplePermissions/PermissionSet/Permission/Subject/@value";

        String subject = evaluateExpression(expression, xmlDocument);

        result.addSubject(subject);

        expression = "/SimplePermissions/PermissionSet/Permission/Resource/@value";

        String resource = evaluateExpression(expression, xmlDocument);

        result.addResource(resource);

        expression = "/SimplePermissions/PermissionSet/Permission/Action/@value";

        String action = evaluateExpression(expression, xmlDocument);

        result.addAction(action);

        return result;

    }

    private String evaluateExpression(String expression, Document xmlDocument){

        try {
            Object value = xPath.compile(expression).evaluate(xmlDocument, XPathConstants.STRING);

            return (String)value;

        } catch (Exception e) {
            LOGGER.error("Could not evaluate expression: " + expression);
        }
        return "";
    }

}
