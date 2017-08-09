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

import java.net.URI;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

public class WFSRestTemplate extends RestTemplate {
    @Override
    protected <T> T doExecute(URI url,
            HttpMethod method,
            RequestCallback callback,
            final ResponseExtractor<T> responseExtractor) throws RestClientException {
        return super.doExecute(url, method, callback, response -> {
            String contentType = response.getHeaders().getFirst("Content-Type");
            if (contentType.startsWith("text/xml")) {
                response.getHeaders().setContentType(MediaType.TEXT_XML);
            }
            return responseExtractor.extractData(response);
        });
    }
}
