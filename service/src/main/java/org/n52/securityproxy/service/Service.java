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

import javax.servlet.http.HttpServlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(value = "/service", consumes = "*/*", produces = "*/*")
public class Service extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 8762101989631385060L;

    private static final Logger LOGGER = LoggerFactory.getLogger(Service.class);

    @RequestMapping(value = "{serviceId}", method = RequestMethod.GET)
    public void get(@PathVariable String serviceId){
        LOGGER.info("Incoming request for service with id: " + serviceId);
    }

//    @Override
//    protected void doGet(HttpServletRequest req,
//            HttpServletResponse resp) throws ServletException, IOException {
//        req.get
//    }
//
//    @Override
//    protected void doPost(HttpServletRequest req,
//            HttpServletResponse resp) throws ServletException, IOException {
//        super.doPost(req, resp);
//    }

}
