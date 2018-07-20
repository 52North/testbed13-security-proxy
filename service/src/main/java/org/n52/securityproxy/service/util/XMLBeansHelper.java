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
package org.n52.securityproxy.service.util;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xmlbeans.XmlOptions;
import org.w3c.dom.Node;

/**
 *
 * @author adewa
 */
public class XMLBeansHelper {

    public static final String NS_WPS_2_0 = "http://www.opengis.net/wps/2.0";

    public static final String NS_WPS_PREFIX = "wps";

    public static final String NS_OWS_2_0 = "http://www.opengis.net/ows/2.0";

    public static final String NS_OWS_PREFIX = "ows";

    public static final String NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";

    public static final String NS_XSI_PREFIX = "xsi";

    public static final String NS_XLINK = "http://www.w3.org/1999/xlink";

    public static final String NS_XLINK_PREFIX = "xlink";


    private static Map<String, String> PREFIXES = new HashMap<String, String>() {

        private static final long serialVersionUID = 5419317972129227659L;

        {
            put(NS_WPS_2_0, NS_WPS_PREFIX);
            put(NS_OWS_2_0, NS_OWS_PREFIX);
            put(NS_XSI, NS_XSI_PREFIX);
            put(NS_XLINK, NS_XLINK_PREFIX);
        }
    };

    public static XmlOptions getWPSXmlOptions() {
        XmlOptions opts = new XmlOptions();
        opts.setSaveNamespacesFirst();
        Map<String,String> prefixes = new HashMap<String,String>();
        prefixes.put(NS_WPS_2_0,NS_WPS_PREFIX);
        prefixes.put(NS_OWS_2_0,NS_OWS_PREFIX);
        prefixes.put(NS_XSI,NS_XSI_PREFIX);
        prefixes.put(NS_XLINK,NS_XLINK_PREFIX);
        opts.setSaveSuggestedPrefixes(prefixes);
        opts.setSaveAggressiveNamespaces();
        opts.setSavePrettyPrint();
        return opts;
    }

    public static String nodeToString(Node node) throws TransformerFactoryConfigurationError, TransformerException {
        StringWriter stringWriter = new StringWriter();
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(new DOMSource(node), new StreamResult(stringWriter));

        return stringWriter.toString();
    }
}
