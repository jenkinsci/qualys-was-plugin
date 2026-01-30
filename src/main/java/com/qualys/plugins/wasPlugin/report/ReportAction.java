package com.qualys.plugins.wasPlugin.report;

import java.io.File;
import java.util.logging.Logger;

import com.qualys.plugins.wasPlugin.QualysAuth.AuthType;
import org.apache.commons.io.FileUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.wasPlugin.QualysClient.QualysCSClient;
import com.qualys.plugins.wasPlugin.QualysClient.QualysCSResponse;
import com.qualys.plugins.wasPlugin.util.Helper;

import hudson.Extension;
import hudson.model.Action;
import hudson.model.Run;
import hudson.util.Secret;
import jenkins.model.RunAction2;
import net.sf.json.JSONObject;
import org.json.XML;
import java.util.ArrayList;
import java.sql.Timestamp;
import org.json.JSONArray;
@Extension
public class ReportAction implements Action, RunAction2 {
	private String scanId;
	private String status;
	private String scanReference;
	private String targetUrl;
	private String webAppId;
	private String scanName;
	private boolean isFailConditionsConfigured;
	private JsonObject evaluationResult;
	private String portalUrl;

	private String reportUrl;

	private String apiServer;
	private String apiUser;
	private Secret apiPass;
    private AuthType authType;
    private String clientId;
    private String clientSecret;
	private boolean useProxy;
	private String proxyServer;
	private int proxyPort;
	private String proxyUsername;
	private Secret proxyPassword;

	private JSONObject scanResult;

	private Run<?, ?> run;

//	private JsonObject kbData = new JsonObject();

	private final static Logger logger = Helper.getLogger(ReportAction.class.getName());

	public ReportAction() { }

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public ReportAction(Run<?, ?> run, String scanId, String webAppId, String scanName, String apiServer, AuthType authType,
                        String apiUser, Secret apiPass, String clientId, String clientSecret, boolean useProxy, String proxyServer, int proxyPort, String proxyUsername, Secret proxyPassword, String portalUrl) {
		this.scanId = scanId;
		this.scanName = scanName;
		this.webAppId = webAppId;
		this.apiServer = apiServer;
		this.apiUser = apiUser;
		this.apiPass = apiPass;
        this.authType = authType;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
		this.useProxy = useProxy;
		this.proxyServer = proxyServer;
		this.proxyPort = proxyPort;
		this.proxyUsername = proxyUsername;
		this.proxyPassword = proxyPassword;
		this.portalUrl = portalUrl;
		this.reportUrl = (portalUrl.endsWith("/")? portalUrl : portalUrl + "/") + "was/#/reports/online-reports/email-report/scan/" + scanId;

		this.run = run;
	}

	public String getScanId() {
		return scanId;
	}

	public String getWebAppId() {
		return webAppId;
	}

	public String getScanName() {
		return scanName;
	}

	public String getReportUrl() {
		return reportUrl;
	}

	//@JavaScriptMethod
	public JSONObject getScanResult() {
		this.scanResult = new JSONObject();
		JsonObject respObj;
		try {
			String filename = run.getArtifactsDir().getAbsolutePath() + File.separator + "qualys_" + scanId + ".json";
			File f = new File(filename);
			Gson gson = new Gson();
			if(f.exists()){
				String resultStr = FileUtils.readFileToString(f);
				respObj = gson.fromJson(resultStr, JsonObject.class);
			}else {
				QualysAuth auth = new QualysAuth();
                auth.setQualysCredentials(apiServer, authType, apiUser, apiPass.getPlainText(), clientId, clientSecret);
				if(useProxy) {
					//int proxyPortInt = Integer.parseInt(proxyPort);
					auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword.getPlainText());
				}
				QualysCSClient qualysClient = new QualysCSClient(auth, System.out);
				QualysCSResponse response = qualysClient.getScanResult(scanId);
				respObj = response.response;
			}

			//if failOnconditions configured then only we will have evalResult
			if(respObj.has("evaluationResult") && !respObj.get("evaluationResult").isJsonNull()){
				scanResult.put("isEvaluationResult", 1);
				JsonElement respEl = respObj.get("evaluationResult");
				JsonObject evalresult = respEl.getAsJsonObject();

				GsonBuilder builder = new GsonBuilder();
				Gson gsonObject = builder.serializeNulls().create(); // for null values

				String sevVulnsJson = gsonObject.toJson(evalresult);
				JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);

				scanResult.put("evaluationResult", JSONObject.fromObject(gsonObject.toJson(sevVulnsElement)));
			}else {
				scanResult.put("isEvaluationResult", 0);
				scanResult.put("evaluationResult", JSONObject.fromObject("{}"));
			}
			JsonElement respEl = respObj.get("ServiceResponse");
			JsonObject serviceResp = respEl.getAsJsonObject();
			JsonElement respCodeObj = serviceResp.get("responseCode");
			if(respCodeObj!= null && !respCodeObj.getAsString().equalsIgnoreCase("SUCCESS")) {
				JsonObject respErr = serviceResp.getAsJsonObject("responseErrorDetails");
				logger.info("Server Response: " + respErr.toString());
				String reason = respErr.get("errorMessage").getAsString();
				throw new Exception(reason);
			}else {
				String[] summaryAttrs = {"linksCrawled", "nbRequests", "resultsStatus", "authStatus"};
				JsonArray dataArr = serviceResp.get("data").getAsJsonArray();
				JsonObject scanObj = dataArr.get(0).getAsJsonObject().get("WasScan").getAsJsonObject();
				JsonObject kbData = batchAndGetKbData(scanObj);

				if(kbData.isJsonNull()){
					logger.info(new Timestamp(System.currentTimeMillis()) + " KB data not found. " );
				}
				else{
					//adding data to file
					JsonObject vulns = scanObj.getAsJsonObject("vulns");
					JsonArray listArr = vulns.getAsJsonArray("list");
					int vulnsCount = vulns.get("count").getAsInt();

					for(int i=0;i<vulnsCount;i++){
						JsonObject listItem = listArr.get(i).getAsJsonObject();
                        JsonObject WasScanVuln = listItem.getAsJsonObject("WasScanVuln");

                        if (WasScanVuln.has("qid") && !WasScanVuln.get("qid").isJsonNull()) {
                            String qid = WasScanVuln.get("qid").getAsString();
                            JsonElement solnElement = kbData.get(qid + "_solution");
                            JsonElement diagnosisElement = kbData.get(qid + "_diagnosis");
                            String soln = (solnElement != null && !solnElement.isJsonNull()) ? solnElement.getAsString() : "";
                            String diagnosis = (diagnosisElement != null && !diagnosisElement.isJsonNull()) ? diagnosisElement.getAsString() : "";

                            if (!soln.isEmpty() && !diagnosis.isEmpty()) {
                                WasScanVuln.addProperty("solution", soln);
                                WasScanVuln.addProperty("diagnosis", diagnosis);
                            } else {
                                logger.info(new Timestamp(System.currentTimeMillis()) + " Kb data not found for qid: " + qid);
                            }
                        }
					}
				}

				//summary
				JsonObject summary = scanObj.get("summary").getAsJsonObject();
				for(int i = 0; i<summaryAttrs.length; i++) {
					try {
						scanResult.put(summaryAttrs[i], summary.get(summaryAttrs[i]).getAsString());
					}
					catch(NullPointerException exc){
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], " - ");
					}
					catch(Exception exc) {
						logger.info("Couldn't fetch " + summaryAttrs[i] + " info. Reason: " + exc.getMessage() );
						scanResult.put(summaryAttrs[i], "Exception: " + exc.getMessage());
					}
				}

				//scan duration
				try {
					String scanDuration = scanObj.get("scanDuration").getAsString();
					long secondsL = Long.parseLong(scanDuration, 10);
					String readableTime = Helper.secondsToReadableTime(secondsL);
					scanResult.put("scanDuration", readableTime);
				}catch(NullPointerException exc){
					logger.info("Couldn't fetch scanDuration info. Reason: " + exc.getMessage() );
					scanResult.put("scanDuration", "Couldn't find the value in API Response.");
				}
				catch(Exception exc) {
					logger.info("Couldn't fetch scanDuration info. Reason: " + exc.getMessage() );
					scanResult.put("scanDuration", "Exception: " + exc.getMessage());
				}

				//scan ref #
				try {
					String scanRef = scanObj.get("reference").getAsString();
					scanResult.put("reference", scanRef);
					scanReference = scanRef;
				}
				catch(NullPointerException exc){
					logger.info("Couldn't fetch reference info. Reason: " + exc.getMessage() );
					scanResult.put("reference", "Couldn't find the value in API Response.");
				}
				catch(Exception exc) {
					logger.info("Couldn't fetch reference info. Reason: " + exc.getMessage() );
					scanResult.put("reference", "Exception: " + exc.getMessage());
				}

				//tagetUrl
				try {
					JsonObject target = scanObj.get("target").getAsJsonObject();
					JsonObject webapp = target.get("webApp").getAsJsonObject();
					String url = webapp.get("url").getAsString();

					scanResult.put("targetUrl", url);
					targetUrl = url;
				}
				catch(NullPointerException exc){
					logger.info("Couldn't fetch targetUrl info. Reason: " + exc.getMessage() );
					scanResult.put("targetUrl", "Couldn't find the value in API Response.");
				}
				catch(Exception exc) {
					logger.info("Couldn't fetch targetUrl info. Reason: " + exc.getMessage() );
					scanResult.put("targetUrl", "Exception: " + exc.getMessage());
				}

				//vulnsBySeverity
				scanResult.put("vulnsBySeverity", JSONObject.fromObject("{\"1\": 0,\"2\": 0,\"3\": 0,\"4\": 0,\"5\": 0}"));
				try {
					JsonObject stats = scanObj.get("stats").getAsJsonObject();
					JsonObject global = stats.get("global").getAsJsonObject();
					JSONObject obj = new JSONObject();
					for(int i=1; i<=5; i++) {
						obj.put(""+i, global.get("nbVulnsLevel"+i).getAsString());
					}
					scanResult.put("vulnsBySeverity", obj);
				}
				catch(NullPointerException exc){
					exc.printStackTrace();
					logger.info("Couldn't fetch Vulnerabilities by Severity info. Reason: " + exc.getMessage() );
					scanResult.put("vulnsBySeverity", "Couldn't find the value in API Response.");
				}
				catch(Exception exc) {
					logger.info("Couldn't fetch Vulnerabilities by Severity info. Reason: " + exc.getMessage() );
					scanResult.put("vulnsBySeverity", "Exception: " + exc.getMessage());
				}

				//vulns stats
				scanResult.put("vulnsTable", JSONObject.fromObject("{list:[]}"));
				String[] vulnsSummary = {"vulns", "sensitiveContents", "igs"};
				for(int i = 0; i<vulnsSummary.length; i++) {
					try {
						JsonObject obj = scanObj.get(vulnsSummary[i]).getAsJsonObject();
						String count = obj.get("count").getAsString();
						scanResult.put(vulnsSummary[i], count);
						if(vulnsSummary[i].equals("vulns") && Integer.parseInt(count) > 0) scanResult.put("vulnsTable", JSONObject.fromObject(gson.toJson(obj)));
					}
					catch(NullPointerException exc){
						logger.info("Couldn't fetch " + vulnsSummary[i] +" info. Reason: " + exc.getMessage() );
						scanResult.put(vulnsSummary[i], "Couldn't find the value in API Response.");
					}
					catch(Exception exc) {
						logger.info("Couldn't fetch " + vulnsSummary[i] +" info. Reason: " + exc.getMessage() );
						scanResult.put(vulnsSummary[i], "Exception: " + exc.getMessage());
					}
				}
			}

		}catch(Exception e) {
			logger.info("Error parsing scan Result: " + e.getMessage());
			scanResult.put("error", e.getMessage());
			e.printStackTrace();
		}
		return scanResult;
	}

	//@JavaScriptMethod
	public JSONObject getStatus() {
		JSONObject statusDetails = new JSONObject();
		try {
			if(status!=null && status.equals("FINISHED")) {
				statusDetails.put("value", "FINISHED");
				statusDetails.put("cssClass", "success");
				statusDetails.put("targetUrl", targetUrl);
				statusDetails.put("reference", scanReference);
			}else {
				statusDetails = parseScanStatus(scanId);
				if(statusDetails.get("value")=="FINISHED") {
					status = "FINISHED";
				}
			}
		}catch(Exception e) {
			e.printStackTrace();
			statusDetails.put("value", e.getMessage());
			statusDetails.put("cssClass", "error");
		}

		return statusDetails;
	}

	public JSONObject parseScanStatus(String scanId) throws Exception {
		JSONObject statusObj = new JSONObject();
		JsonObject result = new JsonObject();
		try {
			QualysAuth auth = new QualysAuth();
            auth.setQualysCredentials(apiServer, authType, apiUser, apiPass.getPlainText(), clientId, clientSecret);
			if(useProxy) {
				//int proxyPortInt = Integer.parseInt(proxyPort);
				auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword.getPlainText());
			}
			QualysCSClient qualysClient = new QualysCSClient(auth, System.out);
			QualysCSResponse resp = qualysClient.getScanDetails(scanId);
			result = resp.response;
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
					JsonObject wasObj = obj.getAsJsonObject("WasScan");
					String status = wasObj.get("status").getAsString();
					try {
						String reference = wasObj.get("reference").getAsString();
						JsonObject targetObj = wasObj.getAsJsonObject("target");
						JsonObject webObj = targetObj.getAsJsonObject("webApp");
						String targetUrl = webObj.get("url").getAsString();
						statusObj.put("reference", reference);
						statusObj.put("targetUrl", targetUrl);
					}catch(Exception e) {
						//these values if not received in status api call will overwritten in getScanResult api call
						if(statusObj.get("reference") != null) statusObj.put("reference", "");
						if(statusObj.get("targetUrl") != null) statusObj.put("targetUrl", "");
					}

					if(status.equals("FINISHED") || status.equals("COMPLETED")) {
						statusObj.put("value", "FINISHED");
						statusObj.put("cssClass", "success");
					}else {
						statusObj.put("value", status);
						statusObj.put("cssClass", "info");
						//resultsStatus
						JsonObject summaryObj = wasObj.getAsJsonObject("summary");
						if(summaryObj != null && !summaryObj.isJsonNull()) {
							JsonElement resultsStatusObj = summaryObj.get("resultsStatus");
							if(resultsStatusObj != null && !resultsStatusObj.isJsonNull()) {
								statusObj.put("resultsStatus", resultsStatusObj.getAsString());
							}
						}
					}
				}
			}
		} catch(Exception e) {
			throw e;
		}
		return statusObj;
	}

	@Override
	public String getIconFileName() {
		return "clipboard.png";
	}

	@Override
	public String getDisplayName() {
		return "Qualys WAS Scan Status";
	}

	@Override
	public String getUrlName() {
		return "qualys_was_scan_status.html";
	}

	public org.json.JSONObject getKbData(String qids){

		QualysAuth auth = new QualysAuth();
		auth.setQualysCredentials(apiServer, apiUser, apiPass.getPlainText());
		if(useProxy) {
			//int proxyPortInt = Integer.parseInt(proxyPort);
			auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword.getPlainText());
		}
		QualysCSClient qualysClient = new QualysCSClient(auth, System.out);

		JsonObject kbData = null;
		String params = "?action=list&details=All&show_supported_modules_info=1&ids="+qids;
		String responseString = qualysClient.getKbData(params);

		org.json.JSONObject jsonResponse = null;
		if (!responseString.isEmpty()) {
			org.json.JSONObject reponseJson = new org.json.JSONObject(responseString);
			String responseStatusCode = reponseJson.get("statusCode").toString();
			String responseBody = reponseJson.get("body").toString();

			if (responseStatusCode.equals("200")) {
				// Convert XML response into JSON format
				jsonResponse = XML.toJSONObject(responseBody);
			}
		}

		return jsonResponse;
	}
	public JsonObject batchAndGetKbData(JsonObject scanResult){
		ArrayList<ArrayList<String>> qidBatches = new ArrayList<>();
		JsonObject batchResult = new JsonObject();
		try {
			Gson gson = new Gson();
			JsonObject vulns = scanResult.getAsJsonObject("vulns");
			JsonArray listArr = vulns.getAsJsonArray("list");
			int vulnsCount = vulns.get("count").getAsInt();

			ArrayList<String> batch = new ArrayList<>();
            for (int i = 0; i < vulnsCount; i++) {
                JsonObject listItem = listArr.get(i).getAsJsonObject();
                if (listItem.has("WasScanVuln") && !listItem.get("WasScanVuln").isJsonNull()) {
                    JsonObject WasScanVuln = listItem.getAsJsonObject("WasScanVuln");
                    if (WasScanVuln.has("qid") && !WasScanVuln.get("qid").isJsonNull()) {
                        String qid = WasScanVuln.get("qid").getAsString();
                        batch.add(qid);

                        if (batch.size() == 500) {
                            ArrayList<String> oneBatch = new ArrayList<>(batch);
                            qidBatches.add(oneBatch);
                            batch.clear();
                        } else if (i == vulnsCount - 1) {
                            ArrayList<String> oneBatch = new ArrayList<>(batch);
                            qidBatches.add(oneBatch);
                            batch.clear();
                        }
                    }
                }
            }
			batchResult = processBatch(qidBatches);
			return batchResult;
		}
		catch (Exception e){
			e.printStackTrace();
			logger.info(new Timestamp(System.currentTimeMillis()) + " Error batchAndGetKbData: " + e.getMessage());
			return batchResult;
		}
	}

	public JsonObject processBatch(ArrayList<ArrayList<String>> qids) {
		JsonObject kbData = new JsonObject();
		try {

			for (int i = 0; i <qids.size() ; i++) {
				String ids = qids.get(i).toString().replace("[", "").replace("]", "").replace(" ", "");
				Gson gson = new Gson();
				org.json.JSONObject kbResult = getKbData(ids); //org.json
				if (kbResult != null) {
					org.json.JSONObject kbOutput = kbResult.getJSONObject("KNOWLEDGE_BASE_VULN_LIST_OUTPUT");
					org.json.JSONObject kbResponse = kbOutput.getJSONObject("RESPONSE");
					org.json.JSONObject kbVulnList = kbResponse.getJSONObject("VULN_LIST");
					String scanResultString = gson.toJson(kbData);
					JSONArray kbVulns = kbVulnList.getJSONArray("VULN");
                    for (int j = 0; j < kbVulns.length(); j++) {
                        org.json.JSONObject listItem = kbVulns.getJSONObject(j);
						String qid = Integer.toString(listItem.getInt("QID"));
						String solution = listItem.getString("SOLUTION");
						String diagnosis = listItem.getString("DIAGNOSIS");
						kbData.addProperty(qid + "_solution", solution);
						kbData.addProperty(qid + "_diagnosis", diagnosis);
					}
					return kbData;
				} else {
					logger.info(new Timestamp(System.currentTimeMillis()) + " Kb data not found for qids: " + qids);
					return kbData;
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
			logger.info(new Timestamp(System.currentTimeMillis()) + " Error processBatch: " + e.getMessage());
			return kbData;
		}
		return kbData;
	}
	//end
}