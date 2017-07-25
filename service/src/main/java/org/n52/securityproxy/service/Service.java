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

import java.util.Base64;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.n52.geoprocessing.oauth2.TokenDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.ServletConfigAware;
import org.springframework.web.context.ServletContextAware;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
@RequestMapping(value = "/service", consumes = "*/*", produces = "*/*")
public class Service implements ServletContextAware, ServletConfigAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(Service.class);
    
    private ServletContext ctx;
    
    private ObjectMapper m;
  
    public void init() {

        m = new ObjectMapper();
    }

    @RequestMapping(value = "{serviceId}", method = RequestMethod.GET)
    public void get(@PathVariable String serviceId, HttpServletRequest req,
            HttpServletResponse res) throws Exception{
        
        LOGGER.info("Incoming request for service with id: " + serviceId);
        
        String token = req.getHeader("Authorization");
        
        if(token == null){
            LOGGER.info("No token was send.");
            return;
        }
        
        DecodedJWT jwt = new TokenDecoder(ctx.getResourceAsStream("/WEB-INF/pubkey/pubkey.pem")).decodeToken(token, "https://bpross-52n.eu.auth0.com/");
        
        String base64EncodedPayload = jwt.getPayload();
        
        byte[] decodedPayloadByteArray = Base64.getDecoder().decode(base64EncodedPayload);
        
        JsonNode rootNode = m.readTree(new String(decodedPayloadByteArray));
        
        JsonNode scopeNode = rootNode.findPath("scope");
        
        String scopeText = scopeNode.textValue();
        
        LOGGER.info(scopeText);
    }

    @Override
    public void setServletConfig(ServletConfig arg0) { }

    @Override
    public void setServletContext(ServletContext arg0) {
        this.ctx = arg0;
    }

}
