package com.qualys.plugins.wasPlugin.QualysClient;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URL;
import java.util.HashMap;
import java.util.logging.Logger;

public class QualysWASClient extends QualysBaseClient {
    HashMap<String, String> apiMap;
    Logger logger = Logger.getLogger(QualysWASClient.class.getName());

    public QualysWASClient(QualysAuth auth) {
        super(auth, System.out);
        this.populateApiMap();
    }

    public QualysWASClient(QualysAuth auth, PrintStream stream) {
        super(auth, stream);
        this.populateApiMap();
    }

    private void populateApiMap() {
        this.apiMap = new HashMap<>();
        this.apiMap.put("getScanResult", "/qps/rest/3.0/download/was/wasscan/");
        this.apiMap.put("getScanDetails", "/qps/rest/3.0/get/was/wasscan/");
        this.apiMap.put("getWebAppCount", "/qps/rest/3.0/count/was/webapp");
        this.apiMap.put("launchScan", "/qps/rest/3.0/launch/was/wasscan");
        this.apiMap.put("getScanStatus", "/qps/rest/3.0/status/was/wasscan/");
        this.apiMap.put("getWebAppDetails", "/qps/rest/3.0/get/was/webapp/");
        this.apiMap.put("listWebApps", "/qps/rest/3.0/search/was/webapp/");
        this.apiMap.put("listOptionProfiles", "/qps/rest/3.0/search/was/optionprofile/");
        this.apiMap.put("listAuthRecords", "/qps/rest/3.0/search/was/webappauthrecord/");
    }

    public QualysWASResponse getScanResult(String scanId) {
        return this.get(this.apiMap.get("getScanResult") + scanId);
    }
    
    public QualysWASResponse getScanDetails(String scanId) {
        return this.get(this.apiMap.get("getScanDetails") + scanId);
    }
    
    public QualysWASResponse getWebAppCount() {
        return this.get(this.apiMap.get("getWebAppCount"));
    }
    
    public QualysWASResponse getScanStatus(String scanId) {
        return this.get(this.apiMap.get("getScanStatus") + scanId);
    }
    
    public QualysWASResponse launchWASScan(JsonObject requestData) {
        return this.post(this.apiMap.get("launchScan"), requestData, null);
    }
    
    public QualysWASResponse getWebAppDetails(String webappId) {
        return this.get(this.apiMap.get("getWebAppDetails") + webappId);
    }
    
    public QualysWASResponse listWebApps(String xml) {
        return this.post(this.apiMap.get("listWebApps"), null, xml);
    }
    
    public QualysWASResponse listOptionProfiles(String xml) {
        return this.post(this.apiMap.get("listOptionProfiles"), null, xml);
    }
    
    public QualysWASResponse listAuthRecords(String xml) {
        return this.post(this.apiMap.get("listAuthRecords"), null, xml);
    }

    public void testConnection() throws Exception{
    	try {
    		QualysWASResponse response = getWebAppCount();
    		if(response.errored) {
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
    	}catch(NullPointerException ne) {
    		ne.printStackTrace();
    		throw new Exception("Please provide valid API and/or Proxy details.");
    	}catch(Exception e) {
    		e.printStackTrace();
    		throw new Exception(e.getMessage());
    	}
    }
    
    private QualysWASResponse get(String apiPath) {
        QualysWASResponse apiResponse = new QualysWASResponse();
        StringBuffer apiResponseString = new StringBuffer();
        CloseableHttpClient httpclient = null;
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            httpclient = this.getHttpClient();	
            
            HttpGet getRequest = new HttpGet(url.toString());
        	getRequest.addHeader("accept", "application/json");
        	getRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	CloseableHttpResponse response = httpclient.execute(getRequest); 
        	apiResponse.responseCode = response.getStatusLine().getStatusCode();
        	logger.info("Server returned with ResponseCode: "+ apiResponse.responseCode);
        	if(response.getEntity()!=null) {
	            BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(),"UTF-8"));
	            String output;
	            while ((output = br.readLine()) != null) {
	                apiResponseString.append(output);
	            }
		        
	            br.close();
	            //httpclient.getConnectionManager().shutdown();
	
	            JsonParser jsonParser = new JsonParser();
	            JsonElement jsonTree = jsonParser.parse(apiResponseString.toString());
	            if (!jsonTree.isJsonObject()) {
	                throw new InvalidAPIResponseException();
	            }	  
	            apiResponse.response = jsonTree.getAsJsonObject();
        	}
            
        }catch (JsonParseException je) {
			apiResponse.errored = true;
            apiResponse.errorMessage = apiResponseString.toString();
		} catch (Exception e) {
            apiResponse.errored = true;
            apiResponse.errorMessage = e.getMessage();
        }         
        
        return apiResponse;
    }
    
    private QualysWASResponse post(String apiPath, JsonObject requestDataJson, String requestXmlString) {
    	QualysWASResponse apiResponse = new QualysWASResponse();
    	StringBuffer apiResponseString = new StringBuffer();
        CloseableHttpClient httpclient = null;
        
        try {
            URL url = this.getAbsoluteUrl(apiPath);
            this.stream.println("Making Request: " + url.toString());
            httpclient = this.getHttpClient();	
            
            HttpPost postRequest = new HttpPost(url.toString());
        	postRequest.addHeader("accept", "application/json");
        	postRequest.addHeader("Authorization", "Basic " +  this.getBasicAuthHeader());
        	Gson gson = new Gson();
        	if(requestDataJson != null) {
        		postRequest.addHeader("Content-Type", "application/json");
	        	StringEntity entity = new StringEntity(gson.toJson(requestDataJson));
	        	postRequest.setEntity(entity);
        	}else if(requestXmlString != null) {
        		postRequest.addHeader("Content-Type", "application/xml");
        		HttpEntity entity = new ByteArrayEntity(requestXmlString.getBytes("UTF-8"));
	        	postRequest.setEntity(entity);
        	}
        	CloseableHttpResponse response = httpclient.execute(postRequest); 
        	apiResponse.responseCode = response.getStatusLine().getStatusCode();
        	logger.info("Server returned with ResponseCode: "+ apiResponse.responseCode);
        	if(response.getEntity()!=null) {
        		BufferedReader br = new BufferedReader(new InputStreamReader(response.getEntity().getContent(),"UTF-8"));
	            String output;
	            while ((output = br.readLine()) != null) {
	            	apiResponseString.append(output);
	            }
	            //httpclient.getConnectionManager().shutdown();
	            br.close();
	            JsonParser jsonParser = new JsonParser();
	            JsonElement jsonTree = jsonParser.parse(apiResponseString.toString());
	            if (!jsonTree.isJsonObject()) {
	                throw new InvalidAPIResponseException();
	            }	  
	            apiResponse.response = jsonTree.getAsJsonObject();
        	}
            
        }catch (JsonParseException je) {
			apiResponse.errored = true;
			apiResponse.errorMessage = apiResponseString.toString();
		} catch (Exception e) {
            apiResponse.errored = true;
            apiResponse.errorMessage = e.getMessage();
        }         
        
        return apiResponse;
    }
   
}
