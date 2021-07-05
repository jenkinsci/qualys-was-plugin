package com.qualys.plugins.wasPlugin;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.wasPlugin.QualysClient.QualysWASClient;
import com.qualys.plugins.wasPlugin.QualysClient.QualysWASResponse;
import com.qualys.plugins.wasPlugin.QualysCriteria.QualysCriteria;
import com.qualys.plugins.wasPlugin.report.ReportAction;
import com.qualys.plugins.wasPlugin.util.Helper;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;

import com.google.gson.Gson;

public class WASScanLauncher{
	private Run<?, ?> run;
    private TaskListener listener;
    private String webAppId;
    private String scanName;
    private String scanType;
    private String authRecord;
    private String optionProfile;
    private String cancelOptions;
    private String authRecordId;
    private String optionProfileId;
    private String cancelHours;
    private int pollingIntervalForVulns;
    private int vulnsTimeout;
    private String portalUrl;
    
    private String apiServer;
    private String apiUser;
    private Secret apiPass;
    private boolean useProxy;
    private String proxyServer;
    private int proxyPort;
    private String proxyUsername;
    private Secret proxyPassword;
    
    private boolean isFailConditionsConfigured;
    private JsonObject criteriaObject;
    
    private QualysWASClient apiClient;
    private boolean failOnScanError;
    
    private final static Logger logger = Helper.getLogger(WASScanLauncher.class.getName());
    private final static int DEFAULT_POLLING_INTERVAL_FOR_VULNS = 5; //5 minutes
    private final static int DEFAULT_TIMEOUT_FOR_VULNS = 60*24; //24Hrs
    
    public WASScanLauncher(Run<?, ?> run, TaskListener listener, String webAppId, String scanName,
    		String scanType, String authRecord, String optionProfile, String cancelOptions, String authRecordId,
    		String optionProfileId, String cancelHours, boolean isFailConditionsConfigured, String pollingIntervalStr, String vulnsTimeoutStr, JsonObject criteriaObject, 
    		String apiServer, String apiUser, String apiPass, boolean useProxy, String proxyServer, int proxyPort, String proxyUsername, String proxyPassword, String portalUrl, boolean failOnScanError) {
    	this.run = run;
        this.listener = listener;
        this.webAppId = webAppId;
        this.scanName = scanName;
        this.scanType = scanType;
        this.authRecord = authRecord;
        this.optionProfile = optionProfile;
        this.cancelOptions = cancelOptions;
        this.authRecordId = authRecordId;
        this.optionProfileId = optionProfileId;
        this.cancelHours = cancelHours;
        
        this.apiServer = apiServer;
        this.apiUser = apiUser;
        this.apiPass = Secret.fromString(apiPass);
        this.useProxy = useProxy;
        this.proxyServer = proxyServer;
        this.proxyPort = proxyPort;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = Secret.fromString(proxyPassword);
        
        this.portalUrl = portalUrl;
        
        if(scanName != null && !scanName.isEmpty() && !scanName.equals("")) {
        	this.scanName += "_[timestamp]";
        }
        
        this.criteriaObject = criteriaObject;
        this.isFailConditionsConfigured = isFailConditionsConfigured;
        
        QualysAuth auth = new QualysAuth();
    	auth.setQualysCredentials(apiServer, apiUser, apiPass);
    	if(useProxy) {
        	//int proxyPortInt = Integer.parseInt(proxyPort);
        	auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword);
    	}
    	this.apiClient = new QualysWASClient(auth, System.out);
        
        this.pollingIntervalForVulns = setTimeoutInMinutes("pollingInterval", DEFAULT_POLLING_INTERVAL_FOR_VULNS, pollingIntervalStr, listener);
		this.vulnsTimeout = setTimeoutInMinutes("vulnsTimeout", DEFAULT_TIMEOUT_FOR_VULNS, vulnsTimeoutStr, listener);
		this.failOnScanError = failOnScanError;
    }
    
    private int setTimeoutInMinutes(String timeoutType, int defaultTimeoutInMins, String timeout, TaskListener listener) {
    	if (!(timeout == null || timeout.isEmpty()) ){
    		try {
    			//if timeout is a regex of form 2*60*60 seconds, calculate the timeout in seconds
    			String[] numbers = timeout.split("\\*");
    			int timeoutInMins = 1;
    			for (int i = 0; i<numbers.length ; ++i) {
    				timeoutInMins *= Long.parseLong(numbers[i]);
    			}
    			return timeoutInMins;
    		} catch(Exception e) {
    			listener.getLogger().println("Invalid " + timeoutType + " time value. Cannot parse -"+e.getMessage());
    			listener.getLogger().println("Using default period of " + (timeoutType.equals("vulnsTimeout") ? "60*24" : defaultTimeoutInMins) + " minutes for " + timeoutType + ".");
    		}
    	}
    	return defaultTimeoutInMins; 
    }
    
	public void getAndProcessLaunchScanResult() throws Exception {
    	try {
    		//#########################################################################
    		String scanId = launchScan();
    		//String scanId = "1953152";
    		if(scanId != null && !scanId.equals("")) {
	    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " New Scan launched successfully. Scan ID: " + scanId);
	    		logger.info("New Scan launched successfully.");
	    		
				//evaluate for failure conditions
				JsonObject evaluationResult = null;
				Boolean buildPassed = true;
	    		if(isFailConditionsConfigured) {
					JsonObject result = fetchScanResult(scanId);
					if(result != null) {
						evaluationResult = evaluateFailurePolicy(result);
						Helper.copyEvaluationResultToFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + scanId, listener.getLogger(), evaluationResult.getAsJsonObject("result"));
						buildPassed = evaluationResult.get("passed").getAsBoolean();
					}
				}
	    		
	    		//create status link on right side
	    		ReportAction action = new ReportAction(run, scanId, webAppId, scanName, apiServer, apiUser, apiPass, useProxy, proxyServer, proxyPort, proxyUsername, proxyPassword, portalUrl);
				run.addAction(action);
				
				if(isFailConditionsConfigured && !buildPassed) {
					String failureMessage = evaluationResult.get("failureMessage").getAsString();
					throw new Exception(failureMessage);
				}
    		} else {
    			throw new Exception("API Error. Could not launch new scan");
    		}
    	} catch (AbortException e) {
    		e.printStackTrace();
    		throw new Exception(e.getMessage());
    	}catch (Exception e) {
    		e.printStackTrace();
    		throw new Exception(e.getMessage());
    	}
    }
	
	private String getBuildFailureMessages(JsonObject result) throws Exception {
    	List<String> failureMessages = new ArrayList<String>();
		if(result.has("qids") && result.get("qids") != null && !result.get("qids").isJsonNull()) {
    		JsonObject qidsObj = result.get("qids").getAsJsonObject();
    		boolean qidsPass = qidsObj.get("result").getAsBoolean();
    		if(!qidsPass) {
    			String found = qidsObj.get("found").getAsString();
    			failureMessages.add("QIDs configured in Failure Conditions were found in the scan result : " + found );
    		}
		}
		
		StringBuffer sevConfigured = new StringBuffer("\nConfigured : ");
		String sevFound = "\nFound : ";
		boolean severityFailed = false;
		for(int i=1; i<=5; i++) {
    		if(result.has("severities") && result.get("severities") != null && !result.get("severities").isJsonNull()) {
    			JsonObject sevObj = result.get("severities").getAsJsonObject();
    			JsonObject severity = sevObj.get(""+i).getAsJsonObject();
    			if(severity.has("configured") && !severity.get("configured").isJsonNull() && severity.get("configured").getAsInt() != -1) {
	    			sevFound += "Severity "+ i +": "+ (severity.get("found").isJsonNull() ? 0 : severity.get("found").getAsString()) + ";";
	    			sevConfigured.append("Severity "+ i +">"+ severity.get("configured").getAsString() + ";");
		    		boolean sevPass = severity.get("result").getAsBoolean();
		    		if(!sevPass) {
		    			severityFailed = true;
		    		}
    			}
    		}
		}
		if(severityFailed) {
			failureMessages.add("The vulnerabilities count by severity exceeded one of the configured threshold value :" + sevConfigured + sevFound);
		}
		
		return StringUtils.join(failureMessages, "\n");
	}
	
	public JsonObject evaluateFailurePolicy(JsonObject result) throws Exception{
		Gson gson = new Gson();
		QualysCriteria criteria = new QualysCriteria(gson.toJson(criteriaObject));
		Boolean passed = criteria.evaluate(result);
		JsonObject obj = new JsonObject();
		obj.add("passed", gson.toJsonTree(passed));
		obj.add("result", criteria.returnObject);
		if(!passed) {
			String failureMessage = getBuildFailureMessages(criteria.getResult());
			obj.addProperty("failureMessage", failureMessage);
		}
		return obj;
	}
	
	public JsonObject fetchScanResult(String scanId) throws Exception {
		long startTime = System.currentTimeMillis();
    	long vulnsTimeoutInMillis = TimeUnit.MINUTES.toMillis(vulnsTimeout);
    	long pollingInMillis = TimeUnit.MINUTES.toMillis(pollingIntervalForVulns);
    	
    	JsonObject scanResult = null;
    	String scanStatus = null;
    	try {
    		//Remove ###############################################################################
    		//int i = 0;
	    	while ((scanStatus = getScanFinishedStatus(scanId)) == null) {
	    		//i = i+1;
	    		//if(i>1) scanId = "3333156";
	    		long endTime = System.currentTimeMillis();
	    		if ((endTime - startTime) > vulnsTimeoutInMillis) {
	    			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Failed to get scan result; timeout of " + vulnsTimeout + " minutes reached.");
	    			throw new Exception("Timeout reached."); 
	    		}
	    		try {
	    			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Waiting for " + pollingIntervalForVulns + " minute(s) before making next attempt for scanResult of scanId:" + scanId + "...");
	    			Thread.sleep(pollingInMillis);
	    		} catch(InterruptedException e) {
	    			throw e;
	    		}
	    	}
    	}
    	catch(Exception e) {
    		throw e;
    	}
    	
    	if (scanStatus.equalsIgnoreCase("finished")) {
    		Gson gson = new Gson();
    		scanResult = getScanResult(scanId);
			String scanResultString = gson .toJson(scanResult);
			Helper.createNewFile(run.getArtifactsDir().getAbsolutePath(), "qualys_" + scanId, scanResultString, listener.getLogger());
    	}else if (scanStatus.equalsIgnoreCase("canceled") && failOnScanError) {
    		throw new Exception("The scan(ScanId: "+ scanId + ") has been canceled.");
    	}else if (scanStatus.equalsIgnoreCase("error") && failOnScanError) {
    		throw new Exception("The scan(ScanId: "+scanId+") is not completed due to an error.");
    	}else if(failOnScanError) {
    		throw new Exception("Qualys WAS Scan(ScanId: "+scanId+") failed with scan status: " + scanStatus);
    	}
	
		return scanResult;
	}
	
	public JsonObject getScanResult(String scanId) {
		JsonObject scanResult = null;
		QualysWASResponse statusResponse = apiClient.getScanResult(scanId);
		scanResult = statusResponse.response;
		return scanResult;
	}
	
	public String getScanFinishedStatus(String scanId) {
		String status = null;
		try {
			QualysWASResponse statusResponse = apiClient.getScanStatus(scanId);
			JsonObject result = statusResponse.response;
			//logger.info("API RESPONSE : " + result.toString());
			JsonElement respEl = result.get("ServiceResponse");
			JsonObject respObj = respEl.getAsJsonObject();
			JsonElement respCodeObj = respObj.get("responseCode");
			if(respCodeObj!= null && !respCodeObj.getAsString().equals("SUCCESS")) {
				JsonObject respErr = respObj.getAsJsonObject("responseErrorDetails"); 
				logger.info("Server Response: " + respErr.toString());
				String reason = respErr.get("errorMessage").getAsString();
				throw new Exception(reason);
			}else {
				JsonArray dataArr = respObj.getAsJsonArray("data");
				JsonObject obj = dataArr.get(0).getAsJsonObject();
				JsonObject scanObj = obj.getAsJsonObject("WasScan");
   				String scanStatus = scanObj.get("status").getAsString();
   				
   				
				String error = "Unknown.";
				try {
   					JsonObject summaryObj = scanObj.getAsJsonObject("summary");
   					error = summaryObj.get("resultsStatus").getAsString();
				}catch(Exception e) {
					logger.info("Could not read error reason from response.");
				}
				if(scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || (scanStatus.equalsIgnoreCase("finished") && !error.equalsIgnoreCase("finished"))) {
					listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Scan Status: "+ scanStatus + ". Reason: " + error);
					return error;
				}else {
					listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Scan Status: "+ scanStatus);
				}
   				return (scanStatus.equalsIgnoreCase("error") || scanStatus.equalsIgnoreCase("canceled") || scanStatus.equalsIgnoreCase("finished")) ? scanStatus : null;
			}
		}catch(Exception e) {
			e.printStackTrace();
			listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Error getting scan status: " + e.getMessage());
		}
		return status;
	}
    
    public String launchScan() throws Exception {
    	JsonObject result = null;;
    	JsonObject requestData = new JsonObject();
    	//required POST parameers - name, type, webappID
    	if(scanType == null || scanType.isEmpty() || scanType.equals("")) {
    		throw new AbortException("Scan Type - Required parameter to launch scan is missing.");
    	}
    	if(scanName == null || scanName.isEmpty() || scanName.equals("")) {
    		throw new AbortException("Scan Name - Required parameter to launch scan is missing.");
    	}
    	if(webAppId == null || webAppId.isEmpty() || webAppId.equals("")) {
    		throw new AbortException("Web App ID - Required parameter to launch scan is missing.");
    	}
    	JsonObject requestObj = new JsonObject();
    	JsonObject data = new JsonObject();
    	JsonObject wasScan = new JsonObject();
    	wasScan.addProperty("type", scanType);
    	//format name : [Job_Name]_jenkins_build_[build_number]_[timestamp]
    	EnvVars env = run.getEnvironment(listener);
    	String job_name = env.get("JOB_NAME");
    	String build_no = env.get("BUILD_NUMBER");
    	String timestamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm").format(new Date());
    	scanName = scanName.replaceAll("(?i)\\[job_name\\]", job_name).replaceAll("(?i)\\[build_number\\]", build_no).replaceAll("(?i)\\[timestamp\\]", timestamp);
    	
    	wasScan.addProperty("name", scanName);
    	
    	JsonObject webappDetails = new JsonObject();
    	JsonObject webapp = new JsonObject();
    	webappDetails.addProperty("id", webAppId);
    	webapp.add("webApp", webappDetails);
    	//Optional POST parameers - Auth record(webAppAuthRecord) = "", "none", "useDefault", "other"
    	if(authRecord != null && authRecord.equals("useDefault")) {
    		JsonObject authRec = new JsonObject();
    		authRec.addProperty("isDefault", "true");
        	webapp.add("webAppAuthRecord", authRec);
    	} else if(authRecord != null && authRecordId != null && authRecord.equals("other") && !authRecordId.isEmpty() && !authRecordId.equals("")) {
    		JsonObject authRec = new JsonObject();
    		authRec.addProperty("id", authRecordId);
        	webapp.add("webAppAuthRecord", authRec);
    	}
    	//cancelOption - "", none, "xhours"
    	if(cancelHours != null && cancelOptions != null && cancelOptions.equals("xhours") && !cancelHours.isEmpty() && !cancelHours.equals("")) {
    		wasScan.addProperty("cancelAfterNHours", cancelHours);
    	}
    	if(optionProfile != null && optionProfileId != null &&  optionProfile.equals("other") && !optionProfileId.isEmpty() && !optionProfileId.equals("")) {
    		JsonObject profRec = new JsonObject();
    		profRec.addProperty("id", optionProfileId);
    		wasScan.add("profile", profRec);
    	}
    	wasScan.add("target", webapp);
    	data.add("WasScan", wasScan);
    	requestObj.add("data", data);
    	requestData.add("ServiceRequest", requestObj);
    	
    	try{
    		//get webapp details to show warning if webapp is configured to use EXTERNAL scanner Appliance
    		Map<String, String> webAppDetialsMap = getWebappDetails(webAppId);
    		if(webAppDetialsMap != null && webappDetails.has("warning")){
    			listener.getLogger().println("WARNING: " + webAppDetialsMap.get("warning"));
    		}
    		
    		String webAppName = webAppDetialsMap.get("webAppName");
    		listener.getLogger().println("Using Web Application: " + webAppName);
    		
    		List<String> scan_ids = new ArrayList<String>();
    		listener.getLogger().println(new Timestamp(System.currentTimeMillis()) + " Calling Launch Scan API with Payload: " + requestData);
    		
    		if(isFailConditionsConfigured) {
    			listener.getLogger().println("Using Build Failure Conditions configuration: " + criteriaObject);
    		}
    		
    		QualysWASResponse response = apiClient.launchWASScan(requestData);
    		result = response.response;
    		//parse result
    		JsonElement respEl = result.get("ServiceResponse");
   			JsonObject respObj = respEl.getAsJsonObject();
   			JsonElement respCodeObj = respObj.get("responseCode");
   			if(respCodeObj!= null && !respCodeObj.getAsString().equals("SUCCESS")) {
   				JsonObject respErr = respObj.getAsJsonObject("responseErrorDetails"); 
   				logger.info("Server Response: " + respErr.toString());
   				throw new AbortException("Error while launching new scan. Server returned: " + respErr);
   			}else {
   				JsonArray dataArr = respObj.get("data").getAsJsonArray();
   				if(dataArr.size() == 0) {
   					return "";
   				}
   				for (int i = 0; i < dataArr.size(); ++i) {
   					JsonObject obj = dataArr.get(i).getAsJsonObject();
	   				JsonObject wasObj = obj.get("WasScan").getAsJsonObject();
	   				String scan_id = wasObj.get("id").getAsString();
	   				scan_ids.add(scan_id);
   				}
   				return String.join(", ", scan_ids);
   			}
    	}catch (Exception e) {
    		throw e;
    	}
    }
    
    public Map<String, String> getWebappDetails(String id) throws Exception {
    	logger.info("Fetching web app details from server.");
    	JsonObject result = null;
    	Map<String,String> webAppDetails = new HashMap<String, String>();
    	try {
    		QualysWASResponse webAppDetialsResp = apiClient.getWebAppDetails(webAppId);
    		result = webAppDetialsResp.response;
    		//logger.info("API RESPONSE : " + result.toString());
    		JsonElement respEl = result.get("ServiceResponse");
   			JsonObject respObj = respEl.getAsJsonObject();
   			JsonElement respCodeObj = respObj.get("responseCode");
   			if(respCodeObj!= null && !respCodeObj.getAsString().equals("SUCCESS")) {
   				JsonObject respErr = respObj.getAsJsonObject("responseErrorDetails"); 
   				logger.info("Server Response: " + respErr.toString());
   				String reason = respErr.get("errorMessage").getAsString();
   				throw new Exception(reason);
   			}else {
   				JsonArray dataArr = respObj.getAsJsonArray("data");
   				for (int i = 0; i < dataArr.size(); ++i) {
   					JsonObject obj = dataArr.get(i).getAsJsonObject();
   					JsonObject webAppObj = obj.getAsJsonObject("WebApp");
	   				String webAppName = webAppObj.get("name").getAsString();
	   				String webAppURL = webAppObj.get("url").getAsString();
	   				JsonElement scannerEl = webAppObj.get("defaultScanner");
	   				if(scannerEl != null && !scannerEl.isJsonNull()) {
		   				JsonObject scannerObj = scannerEl.getAsJsonObject();
		   				String scannerAppliance = scannerObj.get("type").getAsString();
		   				if(scannerAppliance.toLowerCase().equals("external")) {
		   					webAppDetails.put("warning", "Default Scanner Appliance for this webapp is EXTERNAL scanner which will not work and an INTERNAL scanner appliance should be configured as default for the web app.");
		   				}
	   				}
	   				webAppDetails.put("webAppName", webAppName);
	   				webAppDetails.put("webAppURL",webAppURL);
   				}
   			}
        	
    	} catch(Exception e) {
    		logger.info("Exception fetching web app details. Reason: "+ e.getMessage());
    		throw e;
    	}
    	return webAppDetails;
    }
}