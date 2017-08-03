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
package org.n52.securityproxy.service.test;

import java.io.File;
import java.io.IOException;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.junit.Test;
import org.n52.securityproxy.service.util.HttpUtil;
import org.springframework.http.ResponseEntity;

public class ServiceTest {

    static final String WPS_PROXY_BASE_URL="http://localhost:8080/SecurityProxy/service/wps";
    static final String WPS_QS_CAPS = "?service=WPS&request=GetCapabilities";
    static final String WPS_GETCAPS_XML_PATH = "../resources/wpsGetCapabilitiesRequestExample.xml";

    @Test
    public void test() {
        //testGetCapabilities();
        //testGetCapabilitiesPost();
    }

    public void testGetCapabilities(){
        ResponseEntity<String> capsResp = HttpUtil.httpGet(WPS_PROXY_BASE_URL+WPS_QS_CAPS);
        System.out.println(capsResp.getBody());
    }

    public void testGetCapabilitiesPost(){
        File getCapsFile= new File(WPS_GETCAPS_XML_PATH);
        try {
            XmlObject xmlObject = XmlObject.Factory.parse(getCapsFile);
            ResponseEntity<String> capsResp = HttpUtil.httpPost(WPS_PROXY_BASE_URL,xmlObject);
            System.out.println(capsResp.getBody());
        } catch (XmlException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}
