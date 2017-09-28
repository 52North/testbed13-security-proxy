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

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.xmlbeans.impl.common.IOUtil;
import org.n52.securityproxy.model.AWSResource;
import org.n52.securityproxy.model.SimplePermission;
import org.n52.securityproxy.service.util.HttpUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;

public class AWSHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AWSHandler.class);

    private AmazonS3 s3;

    public AWSHandler() {

        LOGGER.debug("User Home: " + System.getProperty("user.home"));

        AWSCredentials credentials = null;
        try {
            credentials = new ProfileCredentialsProvider().getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException("Cannot load the credentials from the credential profiles file. " + "Please make sure that your credentials file is at the correct "
                    + "location (~/.aws/credentials), and is in valid format.", e);
        }

        s3 = new AmazonS3Client(credentials);

    }

    /**
     * if authorized, forwards GET request to aws using access key and secret
     *
     * @param req
     *            request to service
     * @param res
     *            response that should be sent to client
     * @param simplePermission
     * @throws IOException
     *             if response encoding fails
     *
     */
    public void get(HttpServletRequest req,
            HttpServletResponse res, SimplePermission simplePermission, String commonName) throws IOException {

        String originalRequest = HttpUtil.getParameterValue(req, "url");

        AWSResource awsResource = createAWSResourceFromURL(originalRequest);

        Region usWest2 = Region.getRegion(Regions.EU_WEST_1);// TODO get from
                                                             // Request
        s3.setRegion(usWest2);

        String bucketName = awsResource.getBucket();
        String key = awsResource.getKey();

        if(!checkPermission(awsResource, simplePermission, commonName)){
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("You are not authorized to access this resource.");
            return;
        }

        S3Object object = s3.getObject(new GetObjectRequest(bucketName, key));

        res.setContentType(object.getObjectMetadata().getContentType());

        IOUtil.copyCompletely(new InputStreamReader(object.getObjectContent()), new OutputStreamWriter(res.getOutputStream()));
    }

    public AWSResource createAWSResourceFromURL(String awsURL) {

        int httpsIndex = awsURL.indexOf("https://") + 8;
        int amazonawsIndex = awsURL.indexOf(".amazonaws.com/");

        String region = awsURL.substring(httpsIndex, amazonawsIndex);

        String bucketAndKey = awsURL.substring(amazonawsIndex + 15);

        String bucket = bucketAndKey.substring(0, bucketAndKey.indexOf("/"));
        String key = bucketAndKey.substring(bucketAndKey.indexOf("/") + 1, bucketAndKey.length());

        AWSResource resource = new AWSResource(region, bucket, key);

        return resource;
    }

    private boolean checkPermission(AWSResource awsResource,
            SimplePermission simplePermission,
            String commonName) {

        if (!simplePermission.getSubjects().contains(commonName)) {
            return false;
        }
        if (!simplePermission.getResources().contains(awsResource.getKey())) {
            return false;
        }

        return true;

    }

}
