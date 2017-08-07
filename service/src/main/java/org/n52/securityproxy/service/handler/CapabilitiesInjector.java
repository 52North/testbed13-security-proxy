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

import java.util.ArrayList;
import java.util.List;

import net.opengis.ows.x20.DomainType;
import net.opengis.ows.x20.MetadataType;
import net.opengis.ows.x20.OperationDocument.Operation;
import net.opengis.ows.x20.ValuesReferenceDocument.ValuesReference;
import net.opengis.wfs.x20.WFSCapabilitiesDocument;
import net.opengis.wps.x20.CapabilitiesDocument;

import org.n52.securityproxy.service.util.SecurityProxyConfiguration;
import org.n52.securityproxy.service.util.Constants.RequestType;

/**
 *
 * provides methods for injecting security information in Capabilities of OGC
 * WFS and WPS
 *
 * @author staschc
 */
public class CapabilitiesInjector {

    // //
    // Constants for identifier for authentication/authorization method as
    // defined in OGC Testbed 12
    private static final String REF_BEARER = "https://www.tb13.secure-dimensions.de/authnCodeList#OAUTH2_BEARER_TOKEN";

    private static final String REF_CERT = "http://tb12.opengis.net/security/authCodeList#CLIENT_CERTIFICATE";

    private static final String BEARER_URN = "urn:ogc:def:security:authentication:ietf:6750:Bearer";

    private static final String CERT_URN = "urn:ogc:def:tb12:ietf:5246:client_certificate";

    private static final String SCOPES_URN = "urn:ogc:def:security:oauth2:scopes";

    // config
    private SecurityProxyConfiguration conf;

    /**
     * constructor sets config
     *
     */
    public CapabilitiesInjector() {
        conf = SecurityProxyConfiguration.getInstance();
    }

    /**
     * injects security information in operations metadata of capabilities as
     * defined in OGC Testbed 12
     *
     * @param caps
     *            XMLBeans representation of Capabilities document
     *
     */
    public void injectWPSCaps(CapabilitiesDocument caps) {
        Operation[] operationArray = caps.getCapabilities().getOperationsMetadata().getOperationArray();

        for (Operation operation : operationArray) {
            String name = operation.getName();
            if (name.equals(RequestType.DescribeProcess.toString())) {
                List<String> scopes = new ArrayList<String>();
                if (conf.isAuthorizeDescribeProcess()) {
                    scopes.add("DescribeProcess");
                    if (conf.isAuthorizeDescribeProcessID()) {
                        List<String> processIDs = conf.getProcessIdentifiers();
                        for (String processID : processIDs) {
                            scopes.add("DescribeProcess/ProcessID="+processID);
                        }
                    }
                    createBearerConstraint(operation,scopes);
                }
                // TODO reprogram with ACL!!
                if (conf.isCertificateEnabled()) {
                    createCertificateConstraint(operation);
                }
            } else if (name.equals(RequestType.Execute.toString())) {
                List<String> scopes = new ArrayList<String>();
                if (conf.isAuthorizeExecute()) {
                    scopes.add("Execute");
                    if (conf.isAuthorizeDescribeProcessID()) {
                        List<String> processIDs = conf.getProcessIdentifiers();
                        for (String processID : processIDs) {
                            scopes.add("Execute/ProcessID="+processID);
                        }
                    }
                    createBearerConstraint(operation,scopes);
                }
                // TODO reprogram with ACL!!
                if (conf.isCertificateEnabled()) {
                    createCertificateConstraint(operation);
                }
            }
        }
    }

    /**
     * injects security information in operations metadata of WFS capabilities
     * as defined in OGC Testbed 12
     *
     * @param caps
     *            XMLBeans representation of Capabilities document
     *
     */
    public void injectWFSCaps(WFSCapabilitiesDocument caps) {
        if (conf.isAuthorizeExecute()) {
            Operation[] operationArray =
                    (Operation[]) caps.getWFSCapabilities().getOperationsMetadata().getOperationArray();
            List<String> scopes = new ArrayList<String>();
            for (Operation operation : operationArray) {
                String name = operation.getName();

                if (name.equals(RequestType.DescribeFeatureType.toString())) {

                    if (conf.isAuthorizeDescribeFeatureType()) {
                        scopes.add("DescribeFeatureType");
                        if (conf.isAuthorizeDescribeFeatureTypeName()) {
                            List<String> typeNames = conf.getTypeNames();
                            for (String typeName : typeNames) {
                                scopes.add("DescribeFeatureType/TypeName="+typeName);
                            }
                        }
                        createBearerConstraint(operation, scopes);
                    }

                    // TODO reprogram with ACL!!
                    if (conf.isCertificateEnabled()) {
                        createCertificateConstraint(operation);
                    }
                }

                else if (name.equals(RequestType.GetFeature.toString())) {

                    if (conf.isAuthorizeGetFeature()) {
                        scopes.add("GetFeature");
                        if (conf.isAuthorizeDescribeFeatureTypeName()) {
                            List<String> typeNames = conf.getTypeNames();
                            for (String typeName : typeNames) {
                                scopes.add("GetFeature/TypeName="+typeName);
                            }
                        }
                        createBearerConstraint(operation,scopes);
                    }

                    // TODO reprogram with ACL!!
                    if (conf.isCertificateEnabled()) {
                        createCertificateConstraint(operation);
                    }
                }
            }
        }
    }

    /**
     * helper for injecting bearer constraint
     *
     * @param operation
     */
    private void createBearerConstraint(Operation operation,
            List<String> scopes) {

        //add new bearer token constraint
        DomainType constraint = operation.addNewConstraint();
        ValuesReference valueReference = constraint.addNewValuesReference();
        valueReference.setReference(REF_BEARER);
        valueReference.setStringValue(BEARER_URN);
        //TODO check whether Authorization server should be provided like this
        MetadataType metadata = constraint.addNewMetadata();
        metadata.setRole("AuthorizationServer");
        metadata.setHref(conf.getAuthorizationServer());

        //add new scopes constraint
        constraint = operation.addNewConstraint();
        constraint.setName(SCOPES_URN);
        for (String scope:scopes){
            constraint.addNewAllowedValues().addNewValue().setStringValue(scope);
        }
    }

    /**
     * helper for injecting certificate constraint
     *
     * @param operation
     */
    private void createCertificateConstraint(Operation operation) {
        DomainType constraint = operation.addNewConstraint();
        ValuesReference valueReference = constraint.addNewValuesReference();
        valueReference.setReference(REF_CERT);
        valueReference.setStringValue(CERT_URN);
    }

}
