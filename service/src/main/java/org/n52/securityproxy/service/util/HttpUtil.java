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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.apache.xmlbeans.XmlObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

/**
 * util methods for sending HTTP requests and retrieving responses
 *
 * @author staschc
 *
 */
public class HttpUtil {

    /**
     * helper method for posting XML requests
     *
     * @param serviceURL
     *            url to which request should be sent
     * @param request
     *            XMLobject representing request that should be posted
     * @return response
     */
    public static ResponseEntity<String> httpPost(String serviceURL,
            XmlObject request) {
        String xmlString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+request.xmlText();

        RestTemplate restTemplate = new RestTemplate();
        List<HttpMessageConverter<?>> messageConverters = new ArrayList<HttpMessageConverter<?>>();
        messageConverters.add(new StringHttpMessageConverter());
        restTemplate.setMessageConverters(messageConverters);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_XML);
        HttpEntity<String> httpReq = new HttpEntity<String>(xmlString,headers);

        return restTemplate.postForEntity(serviceURL, httpReq, String.class);
    }

    /**
     * helper method for invoking GET service requests
     *
     * @param requestURL
     *            request URL that should be invoked using HTTP GET
     * @return response
     */
    public static ResponseEntity<String> httpGet(String requestURL) {
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(requestURL, String.class);
        return response;
    }

    /**
     * helper for setting headers from Spring response entity to HttpServletResponse
     *
     * @param res
     *          target response
     * @param resEntity
     *          Spring response entity
     */
    public static void setHeaders(HttpServletResponse res,
            ResponseEntity<?> resEntity) {
        HttpHeaders headers = resEntity.getHeaders();
        Iterator<String> keyIterator = headers.keySet().iterator();
        while (keyIterator.hasNext()) {
            String key = keyIterator.next();
            //filter out Transfer-Encoding:chunked
            if (!key.equals("Transfer-Encoding")){
                res.setHeader(key, headers.get(key).get(0));
            }
        }
    }
}
