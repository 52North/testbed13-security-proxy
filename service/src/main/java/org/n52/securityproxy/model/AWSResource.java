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

public class AWSResource {

    private String region;
    private String bucket;
    private String key;

    public AWSResource() {
        //empty constructor
    }

    public AWSResource(String region, String bucket, String key) {
        this.region = region;
        this.bucket = bucket;
        this.key = key;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getBucket() {
        return bucket;
    }

    public void setBucket(String bucket) {
        this.bucket = bucket;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public String toString() {
        String lineSeparator = System.getProperty("line.separator");

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Region: " + region + lineSeparator);
        stringBuilder.append("Bucket: " + bucket + lineSeparator);
        stringBuilder.append("Key: " + key + lineSeparator);

        return stringBuilder.toString();
    }

}
