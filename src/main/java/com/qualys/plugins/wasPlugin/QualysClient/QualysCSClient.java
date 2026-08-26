    package com.qualys.plugins.wasPlugin.QualysClient;

    import com.google.gson.Gson;
    import com.google.gson.JsonElement;

    import com.google.gson.JsonObject;
    import com.google.gson.JsonParseException;
    import com.google.gson.JsonParser;
    import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;

    import com.qualys.plugins.wasPlugin.util.Helper;
    import org.apache.http.HttpEntity;
    import org.apache.http.client.methods.CloseableHttpResponse;
    import org.apache.http.client.methods.HttpGet;
    import org.apache.http.client.methods.HttpPost;
    import org.apache.http.entity.ByteArrayEntity;
    import org.apache.http.entity.StringEntity;
    import org.apache.http.impl.client.CloseableHttpClient;

    import java.io.*;
    import java.net.URL;
    import java.util.HashMap;
    import java.util.Map;
    import java.util.logging.Logger;

    import org.apache.http.util.EntityUtils;

    import org.json.JSONObject;

    public class QualysCSClient extends QualysBaseClient {
        public HashMap<String, String> apiMap;
        Logger logger = Logger.getLogger(QualysCSClient.class.getName());

        public QualysCSClient(QualysAuth auth) {
            super(auth, System.out);
            this.populateApiMap();
        }

        public QualysCSClient(QualysAuth auth, PrintStream stream) {
            super(auth, stream);
            this.populateApiMap();
        }

        private void populateApiMap() {
            this.apiMap = new HashMap<>();
            this.apiMap.put("getOAuthToken", "/auth/oidc");
            this.apiMap.put("getScanResult", "/qps/rest/3.0/download/was/wasscan/");
            this.apiMap.put("getScanDetails", "/qps/rest/3.0/get/was/wasscan/");
            this.apiMap.put("getWebAppCount", "/qps/rest/3.0/count/was/webapp");
            this.apiMap.put("launchScan", "/qps/rest/3.0/launch/was/wasscan");
            this.apiMap.put("getScanStatus", "/qps/rest/3.0/status/was/wasscan/");
            this.apiMap.put("getWebAppDetails", "/qps/rest/3.0/get/was/webapp/");
            this.apiMap.put("listWebApps", "/qps/rest/3.0/search/was/webapp/");
            this.apiMap.put("listOptionProfiles", "/qps/rest/3.0/search/was/optionprofile/");
            this.apiMap.put("listAuthRecords", "/qps/rest/3.0/search/was/webappauthrecord/");
            this.apiMap.put("getKbData","/api/4.0/fo/knowledge_base/vuln/");
        }

        public QualysCSResponse getScanResult(String scanId) {
            return this.get(this.apiMap.get("getScanResult") + scanId);
        }

        public QualysCSResponse getScanDetails(String scanId) {
            return this.get(this.apiMap.get("getScanDetails") + scanId);
        }

        public QualysCSResponse getWebAppCount() {
            return this.get(this.apiMap.get("getWebAppCount"));
        }

        public QualysCSResponse getScanStatus(String scanId) {
            return this.get(this.apiMap.get("getScanStatus") + scanId);
        }

        public QualysCSResponse launchWASScan(JsonObject requestData) {
            return this.post(this.apiMap.get("launchScan"), requestData, null);
        }

        public QualysCSResponse getWebAppDetails(String webappId) {
            return this.get(this.apiMap.get("getWebAppDetails") + webappId);
        }

        public QualysCSResponse listWebApps(String xml) {
            return this.post(this.apiMap.get("listWebApps"), null, xml);
        }

        public QualysCSResponse listOptionProfiles(String xml) {
            return this.post(this.apiMap.get("listOptionProfiles"), null, xml);
        }

        public QualysCSResponse listAuthRecords(String xml) {
            return this.post(this.apiMap.get("listAuthRecords"), null, xml);
        }

        public String getKbData(String params){
            return this.getKbApiCall(this.apiMap.get("getKbData") + params);
        }

        public void testConnection() throws Exception{
            try {
                QualysCSResponse response = getWebAppCount();
                if(response.errored) {
                    String errorMsg = response.errorMessage != null ? response.errorMessage : "";
                    boolean isAuthError = errorMsg.contains("401") || errorMsg.toLowerCase().contains("unauthorized");
                    boolean isNotOIDC = !String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OIDC");
                    if (isAuthError && isNotOIDC) {
                        throw new Exception("Unable to Authenticate User, Check Credentials");
                    }
                    if(response.responseCode > 0)
                        throw new Exception("Please provide valid API and/or Proxy details." + " Server returned with Response code: " +response.responseCode);
                    else
                        throw new Exception("Please provide valid API and/or Proxy details." + " Error Message: " +response.errorMessage);
                }else {
                    JsonObject respObj = response.response;
                    if(response.responseCode < 200 || response.responseCode > 299) {
                        String err_message = respObj.has("errorMessage") ? "Error message: " + respObj.get("errorMessage").getAsString() : "";
                        throw new Exception("HTTP Response code from server: " + response.responseCode + ". " + err_message);
                    }
                    JsonObject serviceResponseObj = respObj.get("ServiceResponse").getAsJsonObject();
                    String responseCodeString = serviceResponseObj.get("responseCode").getAsString();
                    if(!responseCodeString.equalsIgnoreCase("success")) {
                        JsonObject detailsObj = serviceResponseObj.get("responseErrorDetails").getAsJsonObject();
                        String errorMessage = detailsObj.get("errorMessage").getAsString();
                        String errorResolution = detailsObj.get("errorResolution").getAsString();
                        throw new Exception("["+responseCodeString + "] " + errorMessage + ", " + errorResolution);
                    }
                }
            }catch(Exception e) {
                e.printStackTrace();
                throw new Exception(e.getMessage());
            }
        }

        private QualysCSResponse get(String apiPath) {
            QualysCSResponse apiResponse = new QualysCSResponse();
            String apiResponseString = "";
            CloseableHttpClient httpclient = null;

            try {
                URL url = this.getAbsoluteUrl(apiPath);
                httpclient = this.getHttpClient();
                this.stream.println("Making Request: " + url.toString());
                
                String responseBody;
                try {
                    responseBody = this.sendGetRequest(httpclient, url.toString(), this.getCommonHeaders());
                } catch (IOException e) {
                    if (e.getMessage() != null && e.getMessage().contains("401")) {
                        this.stream.println("Received 401 from API, retrying once with fresh token...");
                        this.clearCachedToken();
                        responseBody = this.sendGetRequest(httpclient, url.toString(), this.getCommonHeaders());
                    } else {
                        throw e;
                    }
                }
                apiResponse.responseCode = 200;
                logger.info("Server returned with ResponseCode: "+ apiResponse.responseCode);
                this.stream.println("Server returned with ResponseCode: "+ apiResponse.responseCode);
                this.stream.println("Response entity is not null, processing response body");

                JsonParser jsonParser = new JsonParser();
                JsonElement jsonTree = jsonParser.parse(responseBody);
                if (!jsonTree.isJsonObject()) {
                    throw new InvalidAPIResponseException();
                }
                apiResponse.response = jsonTree.getAsJsonObject();

            }catch (JsonParseException je) {
                apiResponse.errored = true;
                apiResponse.errorMessage = apiResponseString;
            } catch (Exception e) {
                apiResponse.errored = true;
                apiResponse.errorMessage = e.getMessage();
            } finally {
                if (httpclient != null) {
                    try {
                        httpclient.close();
                    } catch (IOException e) {
                        logger.info("Error closing HTTP client: " + e.getMessage());
                    }
                }
            }

            return apiResponse;
        }

        private String getKbApiCall(String apiPath) {
            String responseContent="";
            CloseableHttpClient httpclient = null;

            try {
                URL url = this.getAbsoluteUrl(apiPath, true);
                this.stream.println("Making Request: " + url.toString());
                httpclient = this.getHttpClient();

                Map<String, String> headers = new HashMap<>();
                headers.putAll(this.getCommonHeaders());
                headers.put("X-Requested-With", "Jenkins");

                String responseBody;
                try {
                    responseBody = this.sendGetRequest(httpclient, url.toString(), headers);
                } catch (IOException e) {
                    if (e.getMessage() != null && e.getMessage().contains("401")) {
                        this.stream.println("Received 401 from KB API, retrying once with fresh token...");
                        this.clearCachedToken();
                        headers.putAll(this.getCommonHeaders());
                        headers.put("X-Requested-With", "Jenkins");
                        responseBody = this.sendGetRequest(httpclient, url.toString(), headers);
                    } else {
                        throw e;
                    }
                }

                if (responseBody != null) {
                    JSONObject responseJson = new JSONObject();
                    responseJson.put("statusCode", 200);
                    responseJson.put("body", responseBody);
                    responseContent = responseJson.toString();
                }
                return responseContent;

            }catch (Exception e) {
                logger.info("Error occured in getKBApi call: "+ e.getMessage());
            } finally {
                if (httpclient != null) {
                    try {
                        httpclient.close();
                    } catch (IOException e) {
                        logger.info("Error closing HTTP client: " + e.getMessage());
                    }
                }
            }

            return "";
        }

        private QualysCSResponse post(String apiPath, JsonObject requestDataJson, String requestXmlString) {
            QualysCSResponse apiResponse = new QualysCSResponse();
            String apiResponseString = "";
            CloseableHttpClient httpclient = null;

            try {
                URL url = this.getAbsoluteUrl(apiPath);
                httpclient = this.getHttpClient();
                
                Map<String, String> headers = new HashMap<>();
                headers.putAll(this.getCommonHeaders());
                Gson gson = new Gson();
                this.stream.println("Making Request: " + url.toString());
                
                String body = null;
                if(requestDataJson != null) {
                    headers.put("Content-Type", "application/json");
                    body = gson.toJson(requestDataJson);
                }else if(requestXmlString != null) {
                    headers.put("Content-Type", "application/xml");
                    body = requestXmlString;
                }
                
                String responseBody;
                try {
                    responseBody = this.sendPostRequest(httpclient, url.toString(), headers, body);
                } catch (IOException e) {
                    if (e.getMessage() != null && e.getMessage().contains("401")) {
                        this.stream.println("Received 401 from API, retrying once with fresh token...");
                        this.clearCachedToken();
                        headers = new HashMap<>();
                        headers.putAll(this.getCommonHeaders());
                        if(requestDataJson != null) {
                            headers.put("Content-Type", "application/json");
                        }else if(requestXmlString != null) {
                            headers.put("Content-Type", "application/xml");
                        }
                        responseBody = this.sendPostRequest(httpclient, url.toString(), headers, body);
                    } else {
                        throw e;
                    }
                }
                apiResponse.responseCode = 200;
                logger.info("Server returned with ResponseCode: "+ apiResponse.responseCode);
                apiResponseString = responseBody;

                JsonParser jsonParser = new JsonParser();
                JsonElement jsonTree = jsonParser.parse(apiResponseString);
                if (!jsonTree.isJsonObject()) {
                    throw new InvalidAPIResponseException();
                }
                apiResponse.response = jsonTree.getAsJsonObject();

            }catch (JsonParseException je) {
                apiResponse.errored = true;
                apiResponse.errorMessage = apiResponseString;
            } catch (Exception e) {
                apiResponse.errored = true;
                apiResponse.errorMessage = e.getMessage();
            } finally {
                if (httpclient != null) {
                    try {
                        httpclient.close();
                    } catch (IOException e) {
                        logger.info("Error closing HTTP client: " + e.getMessage());
                    }
                }
            }

            return apiResponse;
        }


    }
