package com.qualys.plugins.wasPlugin.QualysCriteria;

import com.google.gson.*;
import com.qualys.plugins.wasPlugin.util.Helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class QualysCriteria {
	ArrayList<Integer> qidList;
	HashMap<Integer, Integer> severityMap;
	boolean checkPotentialVulns, sevStaus = true;
	ArrayList<Integer> qidExcludeList =  new ArrayList<>(0);
	ArrayList<String> cveExcludeList  = new ArrayList<>(0);
	String excludeBy = "";
	ArrayList<Integer> qidExcludeFound=  new ArrayList<>(0);
	ArrayList<String> cveExcludeFound  = new ArrayList<>(0);
	ArrayList<String> failedReasons  = new ArrayList<>(0);
	Gson gsonObject = new Gson();
	public JsonObject returnObject;
	ArrayList<String> configuredQids;	
	ArrayList<Integer> qidsFound = new ArrayList<>(0);
	
	private final static Logger logger = Helper.getLogger(QualysCriteria.class.getName());
	

	public QualysCriteria(String criteriaJson) throws InvalidCriteriaException {
		JsonParser jsonParser = new JsonParser();
		JsonElement jsonTree = jsonParser.parse(criteriaJson);
		if (!jsonTree.isJsonObject()) {
			throw new InvalidCriteriaException();
		}

		this.setDefaultValues();
		JsonObject jsonObject = jsonTree.getAsJsonObject();
		if (jsonObject.has("failConditions")) {
			JsonObject failConditions = jsonObject.getAsJsonObject("failConditions");
			// QIDs
			if (failConditions.has("qids") && !failConditions.get("qids").isJsonNull()) {
				JsonArray qids = failConditions.getAsJsonArray("qids");				
				JsonObject qidsConf = new JsonObject();
				qidsConf.add("found", null);
				qidsConf.addProperty("result", true);
				for (JsonElement qid : qids) {					
					String qidString = qid.getAsString();
					configuredQids.add(qidString);
					if (qidString.contains("-")) {
						String[] qidElements = qidString.split("-");
						int start = Integer.parseInt(qidElements[0]);
						int end = Integer.parseInt(qidElements[1]);
						for (int i = start; i <= end; i++) {
							this.qidList.add(i);
						}
					} else {
						this.qidList.add(Integer.parseInt(qidString));
					}
				}
				qidsConf.addProperty("configured", String.join(",", configuredQids));
				returnObject.add("qids", qidsConf);
					
			} else {
				System.out.println("'qids' not found in given JSON.");
			}
			
			// Severities
			if (failConditions.has("severities") && !failConditions.get("severities").isJsonNull()) {
				JsonObject severities = failConditions.getAsJsonObject("severities");
				this.severityMap.put(1,
						!(severities.get("1") == null || severities.get("1").isJsonNull())
								? severities.get("1").getAsInt()
								: -1);
				this.severityMap.put(2,
						!(severities.get("2") == null || severities.get("2").isJsonNull())
								? severities.get("2").getAsInt()
								: -1);
				this.severityMap.put(3,
						!(severities.get("3") == null || severities.get("3").isJsonNull())
								? severities.get("3").getAsInt()
								: -1);
				this.severityMap.put(4,
						!(severities.get("4") == null || severities.get("4").isJsonNull())
								? severities.get("4").getAsInt()
								: -1);
				this.severityMap.put(5,
						!(severities.get("5") == null || severities.get("5").isJsonNull())
								? severities.get("5").getAsInt()
								: -1);
				
				JsonObject sevConfigured = new JsonObject();
				for (int i = 5; i >= 1; --i) {
					JsonObject sevJson = new JsonObject();
					if(this.severityMap.get(i).intValue() > -1) {
						sevJson.addProperty("configured", this.severityMap.get(i));
						sevJson.add("found", null);
						sevJson.addProperty("result", true);
						sevConfigured.add(""+i, sevJson);
					}
				}
				returnObject.add("severities", sevConfigured);
			} else {
				this.severityMap.clear();
				this.severityMap.put(1, -1);
				this.severityMap.put(2, -1);
				this.severityMap.put(3, -1);
				this.severityMap.put(4, -1);
				this.severityMap.put(5, -1);
				System.out.println("'severities' not found in given JSON.");
			}
			
		} else {
			System.out.println("'failConditions' not found in given JSON.");
		}
	}

	private void setDefaultValues() {
		this.qidList = new ArrayList<>(0);
		this.configuredQids = new ArrayList<>(0);
		this.severityMap = new HashMap<>();
		

		this.checkPotentialVulns = false;

		this.returnObject = new JsonObject();
		returnObject.add("qids", null);
		returnObject.add("severities", null);
		returnObject.add("vulnsTable", null);

	} // setDefaultValues

	public Boolean evaluate(JsonObject response) {
		Boolean finalStatus=true, sevStatus=true, qidStatus=true, cveStatus=true, softStatus=true;
		JsonObject serviceResponseObj = response.get("ServiceResponse").getAsJsonObject();
		String responseCode = serviceResponseObj.get("responseCode").getAsString();
		
		if (responseCode.equalsIgnoreCase("success")){
			JsonArray dataArr = serviceResponseObj.get("data").getAsJsonArray();
			JsonObject scanObj = dataArr.get(0).getAsJsonObject().get("WasScan").getAsJsonObject();
			JsonObject vulns = scanObj.get("vulns").getAsJsonObject();
			int vulnsCount = vulns.get("count").getAsInt();
			if(vulnsCount > 0 && vulns.has("list") && !vulns.get("list").isJsonNull()) {
				JsonObject statsObj = scanObj.get("stats").getAsJsonObject();
				JsonObject statsData = statsObj.get("global").getAsJsonObject();
				JsonArray vulnsArr = vulns.getAsJsonArray("list");
				returnObject.add("vulnsTable", vulns); // Add Vulnerabilities
				
				// Evaluate Severity 
				sevStatus = this.evaluateSev(statsData);
				qidStatus = this.evaluateQids(vulnsArr);
			}
			
		}

		
		if(!sevStatus || !qidStatus || !cveStatus || !softStatus) {
			finalStatus = false;
		}
		
		return finalStatus;
	}

    private void addSeverities(HashMap<Integer, Integer> counts) {
    	HashMap<Integer, JsonObject> severityResult = new HashMap<Integer, JsonObject>();		
			for (int i = 5; i >= 1; --i) {
				boolean result = true;
				if (this.severityMap.get(i) != -1) {
					if (counts.get(i) > this.severityMap.get(i)) {
						result = false;
						if (sevStaus)
							sevStaus = false;
					}
				}
	
				JsonObject sevJson = new JsonObject();
				//sys
				if(this.severityMap.get(i).intValue() > -1) {
					sevJson.addProperty("configured", this.severityMap.get(i));
				}else {
					sevJson.add("configured", null);
				}
				if(counts.get(i) > 0) {
					sevJson.addProperty("found", counts.get(i));
				}else {
					if(this.severityMap.get(i).intValue() > -1) {
						sevJson.addProperty("found", 0);
					}else {
						sevJson.add("found", null);
					}	
					
				}
				
				sevJson.addProperty("result", result);
				severityResult.put(i, sevJson);	
			}
			GsonBuilder builder = new GsonBuilder();
			gsonObject = builder.serializeNulls().create(); // for null values
			
			String sevVulnsJson = gsonObject.toJson(severityResult);
			JsonElement sevVulnsElement = gsonObject.fromJson(sevVulnsJson, JsonElement.class);
			returnObject.add("severities", sevVulnsElement);
	}

	public String getMyNumbersAsString(ArrayList<Integer> arrayList) {
		if(arrayList.isEmpty()) {
			return "";
		}		
		
		StringBuilder str = new StringBuilder();
		for (int i = 0; i < arrayList.size(); i++) {
			int myNumbersInt = arrayList.get(i);
			str.append(myNumbersInt + ",");
		}
		str.setLength(str.length() - 1);
		return str.toString();
	}
	
	public JsonObject getResult() {
		return this.returnObject;
	}
	
	public Boolean evaluateSev(JsonObject statsData) {
		HashMap<Integer, Integer> evaluationSev = new HashMap<>();
		boolean sevStatus = true;		
		for(int i=1; i <= 5; i++) {
			
			int sevCount = statsData.get("nbVulnsLevel"+i).getAsInt();
			evaluationSev.put(i, sevCount);
			if(!this.severityMap.isEmpty() && this.severityMap.get(i) != -1 && sevCount > this.severityMap.get(i)) {
				sevStatus = false;
				failedReasons.add("Failling this build because found severity" +i+" has more than configured");
		    }
		}
		
		this.addSeverities(evaluationSev);
		
		return sevStatus;
	}
	
	public Boolean evaluateQids(JsonArray vulns) {
		Boolean qidStatus = true;
		
		for (JsonElement vuln : vulns) {
			JsonObject scanObject = vuln.getAsJsonObject();
			JsonObject vulnObject = scanObject.get("WasScanVuln").getAsJsonObject();
				
			Integer qid = 0;
			if (vulnObject.has("qid")) {
				qid = vulnObject.get("qid").getAsInt();
			}
			if (this.qidList.contains(qid)) {
				if(!qidsFound.contains(qid)) qidsFound.add(qid);
			}
		}// for vulns
		
		JsonObject qids = new JsonObject();
		
		if(configuredQids.size() > 0) {
			qids.addProperty("configured", String.join(",", configuredQids)); //configured
		}else {
			qids.add("configured", null); 
		}
		
		String foundQidsString =  this.getMyNumbersAsString(this.qidsFound);
		
		if(!foundQidsString.isEmpty()) {
			qids.addProperty("found", foundQidsString);
		}else {
			qids.add("found", null);  // add null we found nothing
		}
		
		if (qidsFound.size()>0) {				
			qidStatus = false;
			failedReasons.add("Failling this build because found qid(s) - " +qidsFound.toString());
		}
		
		qids.addProperty("result", qidStatus);
		returnObject.add("qids", qids);
	
		return qidStatus;
	}
	
	public ArrayList<String> getBuildFailedReasons() {
		return (ArrayList<String>) this.failedReasons.stream().distinct().collect(Collectors.toList());
    }	
	
	
}
