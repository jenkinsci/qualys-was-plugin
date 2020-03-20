package com.qualys.plugins.wasPlugin;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;
import com.qualys.plugins.wasPlugin.QualysClient.QualysCSClient;
import com.qualys.plugins.wasPlugin.QualysClient.QualysCSResponse;
import com.qualys.plugins.wasPlugin.util.Helper;


import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.reflect.TypeToken;

import com.google.gson.JsonObject;

@Extension
public class WASScanNotifier extends Notifier implements SimpleBuildStep {
	private final static String SCAN_NAME = "[job_name]_jenkins_build_[build_number]";
	private final static int PROXY_PORT = 80;
	private String platform;
	private String apiServer;
    private String credsId;
    private String webAppId;
    private String scanName = SCAN_NAME;
    private String scanType;
    private String authRecord;
    private String optionProfile;
    private String cancelOptions;
    private String authRecordId;
    private String optionProfileId;
    private String cancelHours;
    private String proxyServer;
    private int proxyPort = PROXY_PORT;
    private String proxyCredentialsId;
    private boolean useProxy = false;
    private String pollingInterval;
    private String vulnsTimeout;
    private boolean isFailOnSevereVulns;
    private int severity1Limit;
    private int severity2Limit;
    private int severity3Limit;
    private int severity4Limit;
    private int severity5Limit;
    private boolean isSev1Vulns = false;
    private boolean isSev2Vulns = false;
    private boolean isSev3Vulns = false;
    private boolean isSev4Vulns = false;
    private boolean isSev5Vulns = false;
    
    private boolean isFailOnQidFound;
    private String qidList;
    
    private boolean failOnScanError = true;
    
    private JsonObject criteriaObj;
    
    private final static Logger logger = Helper.getLogger(WASScanNotifier.class.getName());
    
    private static final String xml10pattern = "[^"
            + "\u0009\r\n"
            + "\u0020-\uD7FF"
            + "\uE000-\uFFFD"
            + "\ud800\udc00-\udbff\udfff"
            + "]";
    
    @DataBoundConstructor
    public WASScanNotifier(String apiServer, String credsId) {
        this.apiServer = apiServer;
        this.credsId = credsId;
    }
    
    public WASScanNotifier() { }
    
    public String getPlatform() {
        return platform;
    }
    
    @DataBoundSetter
    public void setPlatform(String platform) {
    	this.platform = platform;
    }
    
    public String getPollingInterval() {
		return pollingInterval;
	}

    @DataBoundSetter
	public void setPollingInterval(String pollingInterval) {
		this.pollingInterval = pollingInterval;
	}

	public String getVulnsTimeout() {
		return vulnsTimeout;
	}

	@DataBoundSetter
	public void setVulnsTimeout(String vulnsTimeout) {
		this.vulnsTimeout = vulnsTimeout;
	}
    
    public boolean getIsFailOnQidFound() {
		return isFailOnQidFound;
	}

	@DataBoundSetter
	public void setIsFailOnQidFound(boolean isFailOnQidFound) {
		this.isFailOnQidFound = isFailOnQidFound;
	}

	public String getQidList() {
		return qidList;
	}

	@DataBoundSetter
	public void setQidList(String qidList) {
		this.qidList = qidList;
	}
	
	@DataBoundSetter
	public void setSeverity1Limit(int severity1Limit) {
		this.severity1Limit = severity1Limit;
	}
	
	public int getSeverity1Limit() {
		return severity1Limit;
	}

	@DataBoundSetter
	public void setSeverity2Limit(int severity2Limit) {
		this.severity2Limit = severity2Limit;
	}
	
	public int getSeverity2Limit() {
		return severity2Limit;
	}
	
	@DataBoundSetter
	public void setSeverity3Limit(int severity3Limit) {
		this.severity3Limit = severity3Limit;
	}
	
	public int getSeverity3Limit() {
		return severity3Limit;
	}
	
	@DataBoundSetter
	public void setSeverity4Limit(int severity4Limit) {
		this.severity4Limit = severity4Limit;
	}
	
	public int getSeverity4Limit() {
		return severity4Limit;
	}
	
	@DataBoundSetter
	public void setSeverity5Limit(int severity5Limit) {
		this.severity5Limit = severity5Limit;
	}
	
	public int getSeverity5Limit() {
		return severity5Limit;
	}
	
	@DataBoundSetter
	public void setIsSev1Vulns(boolean isSev1Vulns) {
		this.isSev1Vulns = isSev1Vulns;
	}

	public boolean getIsSev1Vulns() {
		return isSev1Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev2Vulns(boolean isSev2Vulns) {
		this.isSev2Vulns = isSev2Vulns;
	}

	public boolean getIsSev2Vulns() {
		return isSev2Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev3Vulns(boolean isSev3Vulns) {
		this.isSev3Vulns = isSev3Vulns;
	}

	public boolean getIsSev3Vulns() {
		return isSev3Vulns;
	}
	
	
	@DataBoundSetter
	public void setIsSev4Vulns(boolean isSev4Vulns) {
		this.isSev4Vulns = isSev4Vulns;
	}

	public boolean getIsSev4Vulns() {
		return isSev4Vulns;
	}
	
	@DataBoundSetter
	public void setIsSev5Vulns(boolean isSev5Vulns) {
		this.isSev5Vulns = isSev5Vulns;
	}

	public boolean getIsSev5Vulns() {
		return isSev5Vulns;
	}

    @DataBoundSetter
    public void setCancelHours(String cancelHours) {
    	this.cancelHours = cancelHours;
    }
    
    public String getCancelHours() {
    	return cancelHours;
    }
    
    @DataBoundSetter
    public void setOptionProfileId(String optionProfileId) {
    	this.optionProfileId = optionProfileId;
    }
    
    public String getOptionProfileId() {
    	return optionProfileId;
    }
    
    @DataBoundSetter
    public void setAuthRecordId(String authRecordId) {
    	this.authRecordId = authRecordId;
    }
    
    public String getAuthRecordId() {
    	return authRecordId;
    }
    
    @DataBoundSetter
    public void setCancelOptions(String cancelOptions) {
    	this.cancelOptions = cancelOptions;
    }
    
    public String getCancelOptions() {
    	return cancelOptions;
    }
    
    @DataBoundSetter
    public void setOptionProfile(String optionProfile) {
    	this.optionProfile = optionProfile;
    }
    
    public String getOptionProfile() {
    	return optionProfile;
    }
    
    @DataBoundSetter
    public void setAuthRecord(String authRecord) {
    	this.authRecord = authRecord;
    }
    
    public String getAuthRecord() {
    	return authRecord;
    }
    
    @DataBoundSetter
    public void setScanType(String scanType) {
    	this.scanType = scanType;
    }
    
    public String getScanType() {
    	return scanType;
    }
    
    @DataBoundSetter
    public void setScanName(String scanName) {
    	scanName = StringUtils.isBlank(scanName) ? SCAN_NAME : scanName;
    	this.scanName = scanName;
    }
    
    public String getScanName() {
    	return scanName;
    }
    
    @DataBoundSetter
    public void setWebAppId(String webAppId) {
    	logger.info("Set webApp ID to " + webAppId);
    	this.webAppId = webAppId;
    }
    
    @DataBoundSetter
    public void setApiServer(String server) {
    	this.apiServer = server.trim();
    }
    
    public String getWebAppId() {
    	return webAppId;
    }
    
    public String getApiServer() {
        logger.info("Returning apiServer = " + apiServer);
        return apiServer;
    }
    
    public String getProxyServer() {
		return proxyServer;
	}

	@DataBoundSetter
	public void setProxyServer(String proxyServer) {
		this.proxyServer = proxyServer;
	}
	
	public int getProxyPort() {
		return proxyPort;
	}

	@DataBoundSetter
	public void setProxyPort(int proxyPort) {
		proxyPort = proxyPort <= 0 ? PROXY_PORT : proxyPort;
		this.proxyPort = proxyPort;
	}
	
	public String getProxyCredentialsId() {
		return proxyCredentialsId;
	}

	@DataBoundSetter
	public void setProxyCredentialsId(String proxyCredentialsId) {
		this.proxyCredentialsId = proxyCredentialsId;
	}
	
	public boolean getUseProxy() {
		return useProxy;
	}

	@DataBoundSetter
	public void setUseProxy(boolean useProxy) {
		this.useProxy = useProxy;
	}
	
	@DataBoundSetter
	public void setCredsId(String cred) {
    	this.credsId = cred;
    }

	public String getCredsId() {
		return credsId;
	}
	
	@DataBoundSetter
	public void setFailOnScanError(boolean failOnScanError) {
		this.failOnScanError = failOnScanError;
	}
	
	public boolean getFailOnScanError() {
		return failOnScanError;
	}
	
	public JsonObject getCriteriaAsJsonObject() {
    	JsonObject obj = new JsonObject();
    	
    	JsonObject failConditionsObj = new JsonObject();
    	Gson gson = new Gson();
    	if(isFailOnQidFound) {
	    	if(this.qidList == null || this.qidList.isEmpty()) {
	    		JsonElement empty = new JsonArray();
	    		failConditionsObj.add("qids", empty);
	    	}else {
		    	List<String> qids = Arrays.asList(this.qidList.split(","));
		    	qids.replaceAll(String::trim);
		    	JsonElement element = gson.toJsonTree(qids, new TypeToken<List<String>>() {}.getType());
		    	failConditionsObj.add("qids", element);
	    	}
    	}
    	if(isFailOnSevereVulns) {
	    	JsonObject severities = new JsonObject();
	    	if(this.isSev5Vulns) severities.addProperty("5", this.severity5Limit);
	    	if(this.isSev4Vulns) severities.addProperty("4", this.severity4Limit);
	    	if(this.isSev3Vulns) severities.addProperty("3", this.severity3Limit);
	    	if(this.isSev2Vulns) severities.addProperty("2", this.severity2Limit);
	    	if(this.isSev1Vulns) severities.addProperty("1", this.severity1Limit);
	    	failConditionsObj.add("severities", severities);
    	}
    	if(failOnScanError) {
    		failConditionsObj.addProperty("failOnScanError", true);
    	}
    	obj.add("failConditions",failConditionsObj);
    	
    	logger.info("Criteria Object to common library: " + obj);
    	return obj;
    }
    
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
    	private final String URL_REGEX = "^(https)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private final String PROXY_REGEX = "^((https?)://)?[-a-zA-Z0-9+&@#/%?=~_|!,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
        private final String TIMEOUT_PERIOD_REGEX = "^(\\d+[*]?)*(?<!\\*)$";
        
    	@Override
        public String getDisplayName() {
    		return "Scan web applications with Qualys WAS";
        }

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}
		
		public boolean isNonUTF8String(String string) {
        	if(string != null && !string.isEmpty()) {
	        	try 
	        	{
	        	    byte[] bytes = string.getBytes("UTF-8");
	        	} 
	        	catch (UnsupportedEncodingException e)
	        	{
	        	    return true;
	        	}
        	}
        	return false;
        }
		
		public FormValidation doCheckPollingInterval(@QueryParameter String pollingInterval) {
            try {
            	String pollingIntervalVal = pollingInterval.trim(); 
            	if (pollingIntervalVal.equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(pollingIntervalVal);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + pollingInterval + ", reason = " + e);
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckVulnsTimeout(@QueryParameter String vulnsTimeout) {
            String vulnsTimeoutVal = vulnsTimeout.trim();
        	try {
            	 if (vulnsTimeoutVal.equals("")) {
             	    return FormValidation.ok();
            	 }
            	 Pattern patt = Pattern.compile(TIMEOUT_PERIOD_REGEX);
                 Matcher matcher = patt.matcher(vulnsTimeoutVal);
             	
                 if (!(matcher.matches())) {
                     return FormValidation.error("Timeout period is not valid!");
                 } else {
                     return FormValidation.ok();
                 }
            } catch (Exception e) {
            	return FormValidation.error("Timeout period string : " + vulnsTimeout + ", reason = " + e);
            }
        }
        
        public FormValidation doCheckApiServer(@QueryParameter String apiServer) {
        	if(isNonUTF8String(apiServer)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
        		String server = apiServer != null ? apiServer.trim() : "";
            	Pattern patt = Pattern.compile(URL_REGEX);
                Matcher matcher = patt.matcher(server);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Server name is not valid!");
                } else {
                	 return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckCredsId(@QueryParameter String credsId) {
            try {
                if (credsId.trim().equals("")) {
                    return FormValidation.error("API Credentials cannot be empty.");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        @POST
        public ListBoxModel doFillCredsIdItems(@AncestorInPath Item item, @QueryParameter String credsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Item.CONFIGURE)) {
                	return result.add(credsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(credsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(credsId));
        }
        
        @POST
        public ListBoxModel doFillProxyCredentialsIdItems(@AncestorInPath Item item, @QueryParameter String proxyCredentialsId) {
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
            	if (!Jenkins.getInstance().hasPermission(Item.CONFIGURE)) {
                	return result.add(proxyCredentialsId);
                }
            } else {
            	if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                	return result.add(proxyCredentialsId);
                }
            }
            return result
                    .withEmptySelection()
                    .withAll(CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class, item, null, Collections.<DomainRequirement>emptyList()))
                    .withMatching(CredentialsMatchers.withId(proxyCredentialsId));
        }
        
        public QualysCSClient getQualysClient(String apiServer, String credsId, boolean useProxy, String proxyServer,
        		String proxyPort, String proxyCredentialsId, Item item) {
        	String apiUser = "";
    		String apiPass = "";
    		String proxyUsername = "";
    		String proxyPassword = "";
    		if (StringUtils.isNotEmpty(credsId)) {

                StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                StandardUsernamePasswordCredentials.class,
                                item,
                                null,
                                Collections.<DomainRequirement>emptyList()),
                        CredentialsMatchers.withId(credsId));

                apiUser = (c != null ? c.getUsername() : "");
                apiPass = (c != null ? c.getPassword().getPlainText() : "");
            }
    		if (StringUtils.isNotEmpty(proxyCredentialsId)) {

                StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                StandardUsernamePasswordCredentials.class,
                                item,
                                null,
                                Collections.<DomainRequirement>emptyList()),
                        CredentialsMatchers.withId(proxyCredentialsId));

                proxyUsername = (c != null ? c.getUsername() : "");
                proxyPassword = (c != null ? c.getPassword().getPlainText() : "");
            }
    		if(StringUtils.isNotBlank(apiServer) && StringUtils.isNotBlank(apiUser) && StringUtils.isNotBlank(apiPass)) {
        		if (apiServer.endsWith("/")) apiServer = apiServer.substring(0, apiServer.length() - 1);
        		QualysAuth auth = new QualysAuth();
            	auth.setQualysCredentials(apiServer, apiUser, apiPass);
            	if(useProxy) {
            		int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
                	auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
            	}
            	QualysCSClient client = new QualysCSClient(auth, System.out);
            	return client;
    		}
    		return null;
        }
        
       public ListBoxModel doFillOptionProfileItems() {
        	ListBoxModel model = new ListBoxModel();
        	Option e1 = new Option("Other", "other");
        	Option e2 = new Option("Use Default", "useDefault");
        	model.add(e2);model.add(e1);
        	return model;
        }
        
        public ListBoxModel doFillCancelHoursItems() {
        	ListBoxModel model = new ListBoxModel();
        	for(int i=1; i<=24; i++) {
	        	Option e = new Option(Integer.toString(i), Integer.toString(i));
	        	model.add(e);
        	}
        	return model;
        }
        
        public ListBoxModel doFillPlatformItems() {
        	ListBoxModel model = new ListBoxModel();
        	for(Map<String, String> platform: getPlatforms()) {
        		Option e = new Option(platform.get("name"), platform.get("code"));
            	model.add(e);
        	}
        	return model;
        }
        
        public ListBoxModel doFillScanTypeItems() {
        	ListBoxModel model = new ListBoxModel();
        	Option e1 = new Option("VULNERABILITY", "VULNERABILITY");
        	Option e2 = new Option("DISCOVERY", "DISCOVERY");
        	model.add(e1);model.add(e2);
        	return model;
        }
        
        public ListBoxModel doFillCancelOptionsItems() {
        	ListBoxModel model = new ListBoxModel();
        	Option e1 = new Option("None", "none");
        	Option e2 = new Option("Cancel After X Hours", "xhours");
        	model.add(e1);model.add(e2);
        	return model;
        }
        
        public ListBoxModel doFillAuthRecordItems() {
        	ListBoxModel model = new ListBoxModel();
        	Option e1 = new Option("None", "none");
        	Option e2 = new Option("Use Default", "useDefault");
        	Option e3 = new Option("Other", "other");
        	model.add(e1);model.add(e2);model.add(e3);
        	return model;
        }
        
        public QualysCSResponse callAPIs(String api, QualysCSClient client, String id) {
        	QualysCSResponse resp = null;
        	String xmlReqData = id==null ? null : "<ServiceRequest> <filters> <Criteria field=\"id\" operator=\"GREATER\">" + id + "</Criteria> </filters> </ServiceRequest>";
        	
        	if(client != null) {
        		switch(api) {
				case "webAppList":
					resp = client.listWebApps(xmlReqData);
					break;
				case "authRecordList":
					resp = client.listAuthRecords(xmlReqData);
					break;
				case "profileList":
					resp = client.listOptionProfiles(xmlReqData);
					break;
				}
        	}
			return resp;
        }
        
        public JsonArray getDataList(String api, QualysCSClient client) {
        	boolean hasMoreRecords = true;
        	int page = 0;
        	String lastId = null;
        	JsonArray dataList = new JsonArray();
        	try {
            	while(hasMoreRecords) {
            		int retry = 0;
	            	while(retry < 3) {
	            		if(retry > 0 ) logger.info("Retrying "+ api + " call: " + retry);
	        			QualysCSResponse resp = callAPIs(api, client, lastId);        			
	        			retry ++;
	        			
	        			logger.info("Response code received for API "+ api + " call [page="+page+"]: " + resp.responseCode);
	    				hasMoreRecords = false;
	    				if(resp != null && resp.responseCode == 200) {
		            		JsonObject response = resp.response;
		            		JsonObject serviceResp = response.getAsJsonObject("ServiceResponse");
		            		String responseCode = serviceResp.get("responseCode").getAsString();
		            		if(responseCode.equalsIgnoreCase("success")) {
		            			int count = serviceResp.get("count").getAsInt();
		            			if(count > 0) {
			            			hasMoreRecords = serviceResp.get("hasMoreRecords").getAsBoolean();
			            			lastId = hasMoreRecords ? serviceResp.get("lastId").getAsString() : null;
			            			JsonArray arr = serviceResp.get("data").getAsJsonArray();
				            		dataList.addAll(arr);
		            			}
		            			break;
		            		}
		            	}
	            	}
	            	page++;
            	}
        	} catch(Exception e) {
        		e.printStackTrace();
        	}
			return dataList;
        }
        
        @POST
        public ListBoxModel doFillWebAppIdItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	try {
        		if(filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			String server = apiServer != null ? apiServer.trim() : "";
            		//set apiServer URL according to platform
                	if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                	}
        			QualysCSClient client = getQualysClient(server, credsId, useProxy, proxyServer, proxyPort, proxyCredentialsId, item);
	        		logger.info("Fetching web applications list ... ");
	        		JsonArray dataList = getDataList("webAppList", client);
	        		for(JsonElement  webapp : dataList) {
	        			JsonObject obj = webapp.getAsJsonObject();
	        			JsonObject webAppObj = obj.getAsJsonObject("WebApp");
	        			String id = webAppObj.get("id").getAsString();
	        			String name = webAppObj.get("name").getAsString();
	        			String label = name.replaceAll(xml10pattern, "*");
	        			Option e = new Option(label, id);
	                	model.add(e);
	        		}
        		}
        	} catch(Exception e) {
        		e.printStackTrace();
        		//return object;
        	}
        	
        	model.sort(Helper.OptionItemmsComparator);
        	return model.withEmptySelection();
        }
        
        @POST
        public ListBoxModel doFillAuthRecordIdItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	try {
        		if(filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			String server = apiServer != null ? apiServer.trim() : "";
            		//set apiServer URL according to platform
                	if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                	}
        			QualysCSClient client = getQualysClient(server, credsId, useProxy, proxyServer, proxyPort, proxyCredentialsId, item);
	        		logger.info("Fetching Auth Records list ... ");
	        		JsonArray dataList = getDataList("authRecordList", client);
	        		for(JsonElement  webapp : dataList) {
	        			JsonObject obj = webapp.getAsJsonObject();
	        			JsonObject webAppObj = obj.getAsJsonObject("WebAppAuthRecord");
	        			String id = webAppObj.get("id").getAsString();
	        			String name = webAppObj.get("name").getAsString();
	        			Charset charset = Charset.forName("UTF-8");
	        			String label = name.replaceAll(xml10pattern, "*");
	        			
	        			Option e = new Option(label, id);
	                	model.add(e);
	        		}
        		}
        	} catch(Exception e) {
        		e.printStackTrace();
        		//return object;
        	}
        	model.sort(Helper.OptionItemmsComparator);
        	return model.withEmptySelection();
        }
        
        @POST
        public ListBoxModel doFillOptionProfileIdItems(@AncestorInPath Item item, @QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId, @QueryParameter String proxyServer, 
        		@QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy) {
        	
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	StandardListBoxModel model = new StandardListBoxModel();
        	try {
        		if(filledInputs(platform, apiServer, credsId, useProxy, proxyServer, proxyPort)) {
        			String server = apiServer != null ? apiServer.trim() : "";
            		//set apiServer URL according to platform
                	if(!platform.equalsIgnoreCase("pcp")) {
                		Map<String, String> platformObj = Helper.platformsList.get(platform);
                		server = platformObj.get("url");
                	}
        			QualysCSClient client = getQualysClient(server, credsId, useProxy, proxyServer, proxyPort, proxyCredentialsId, item);
	        		logger.info("Fetching Option Profiles list ... ");
	        		JsonArray dataList = getDataList("profileList", client);
	        		for(JsonElement  webapp : dataList) {
	        			JsonObject obj = webapp.getAsJsonObject();
	        			JsonObject webAppObj = obj.getAsJsonObject("OptionProfile");
	        			String id = webAppObj.get("id").getAsString();
	        			String name = webAppObj.get("name").getAsString();
	        			Charset charset = Charset.forName("UTF-8");
	        			String label = name.replaceAll(xml10pattern, "*");
	        			Option e = new Option(label, id);
	                	model.add(e);
	        		}
        		}
        	} catch(Exception e) {
        		e.printStackTrace();
        		//return object;
        	}
        	model.sort(Helper.OptionItemmsComparator);
        	return model.withEmptySelection();
        }
        
        public boolean filledInputs(String platform, String apiServer, String credsId, boolean useProxy, String proxyServer, String proxyPort) {
			if(platform.equalsIgnoreCase("pcp") && StringUtils.isBlank(apiServer)) return false;
        	if(StringUtils.isBlank(credsId)) return false;
			if(useProxy && StringUtils.isBlank(proxyServer)) return false;
        	return true;
        }
        
        public FormValidation doCheckWebAppId(@QueryParameter String webAppId) {
        	try {
        		if (webAppId != null && StringUtils.isNotBlank(webAppId)) {
        			int webAppIdInt = Integer.parseInt(webAppId);
        			if(webAppIdInt < 1 ) {
        				return FormValidation.error("Please select a valid web application");
        			}
        		}else {
        			return FormValidation.error("Please select a valid web application");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid web application");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckScanName(@QueryParameter String scanName) {
        	if(isNonUTF8String(scanName)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
                if (scanName.trim().equals("")) {
                    return FormValidation.error("Scan Name cannot be empty.");
                } else {
                	if(scanName.length() > 256) {
                		return FormValidation.error("Scan Name length must be of 256 or less characters.");
                	}
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }
        
        public FormValidation doCheckCancelHours(@QueryParameter String cancelHours) {
        	try {
        		if (cancelHours != null && !cancelHours.isEmpty()) {
        			int hoursInputInt = Integer.parseInt(cancelHours);
        			if(hoursInputInt < 1 || hoursInputInt > 24) {
        				return FormValidation.error("Please enter a number between range 1 to 24.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        @POST
        public FormValidation doCheckConnection(@QueryParameter String platform, @QueryParameter String apiServer, @QueryParameter String credsId,
        		@QueryParameter String proxyServer, @QueryParameter String proxyPort, @QueryParameter String proxyCredentialsId, @QueryParameter boolean useProxy, @AncestorInPath Item item) {
        	
        	Jenkins.getInstance().checkPermission(Item.CONFIGURE);
        	try {
        		String server = apiServer != null ? apiServer.trim() : "";
        		//set apiServer URL according to platform
            	if(!platform.equalsIgnoreCase("pcp")) {
            		Map<String, String> platformObj = Helper.platformsList.get(platform);
            		server = platformObj.get("url");
            	}
            	logger.info("Using qualys API Server URL: " + server);
        		logger.info("Using credentials id: " + credsId);
        		String apiUser = "";
        		String apiPass = "";
        		if (StringUtils.isNotEmpty(credsId)) {

                    StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                    StandardUsernamePasswordCredentials.class,
                                    item,
                                    null,
                                    Collections.<DomainRequirement>emptyList()),
                            CredentialsMatchers.withId(credsId));

                    apiUser = (c != null ? c.getUsername() : "");
                    apiPass = (c != null ? c.getPassword().getPlainText() : "");
                }
        		logger.info("UserName: " + apiUser);
            	int proxyPortInt = (doCheckProxyPort(proxyPort)==FormValidation.ok()) ? Integer.parseInt(proxyPort) : 80;
            	QualysAuth auth = new QualysAuth();
            	auth.setQualysCredentials(server, apiUser, apiPass);
            	if(useProxy) {
            		String proxyUsername = "";
                	String proxyPassword = "";
            		if (StringUtils.isNotEmpty(proxyCredentialsId)) {

                        StandardUsernamePasswordCredentials c = CredentialsMatchers.firstOrNull(CredentialsProvider.lookupCredentials(
                                        StandardUsernamePasswordCredentials.class,
                                        item,
                                        null,
                                        Collections.<DomainRequirement>emptyList()),
                                CredentialsMatchers.withId(proxyCredentialsId));

                        proxyUsername = (c != null ? c.getUsername() : "");
                        proxyPassword = (c != null ? c.getPassword().getPlainText() : "");
                    }
                	auth.setProxyCredentials(proxyServer, proxyPortInt, proxyUsername, proxyPassword);
            	}
            	QualysCSClient client = new QualysCSClient(auth, System.out);
            	client.testConnection();
            	return FormValidation.ok("Connection test successful!");
                
            } catch (Exception e) {
            	e.printStackTrace();
            	return FormValidation.error("Connection test failed. (Reason: " + e.getMessage() + ")");
            }
        }
        
        public FormValidation doCheckProxyServer(@QueryParameter String proxyServer) {
        	if(isNonUTF8String(proxyServer)) {
            	return FormValidation.error("Please provide valid UTF-8 string value.");
            }
        	try {
            	Pattern patt = Pattern.compile(PROXY_REGEX);
                Matcher matcher = patt.matcher(proxyServer);
            	
                if (!(matcher.matches())) {
                    return FormValidation.error("Enter valid server url!");
                } else {
                    return FormValidation.ok();
                }
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        public FormValidation doCheckProxyPort(@QueryParameter String proxyPort) {
        	try {
        		if (proxyPort != null && !proxyPort.isEmpty() && proxyPort.trim().length() > 0) {
        			int proxyPortInt = Integer.parseInt(proxyPort);
        			if(proxyPortInt < 1 || proxyPortInt > 65535) {
        				return FormValidation.error("Please enter a valid port number!");
        			}
        		}else {
        			return FormValidation.error("Please enter a valid port number!");
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid port number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity1Limit(@QueryParameter String severity1Limit) {
        	try {
        		if (severity1Limit != null && !severity1Limit.isEmpty()) {
        			int severity1LimitInt = Integer.parseInt(severity1Limit);
        			if(severity1LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity2Limit(@QueryParameter String severity2Limit) {
        	try {
        		if (severity2Limit != null && !severity2Limit.isEmpty()) {
        			int severity2LimitInt = Integer.parseInt(severity2Limit);
        			if(severity2LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity3Limit(@QueryParameter String severity3Limit) {
        	try {
        		if (severity3Limit != null && !severity3Limit.isEmpty()) {
        			int severity3LimitInt = Integer.parseInt(severity3Limit);
        			if(severity3LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity4Limit(@QueryParameter String severity4Limit) {
        	try {
        		if (severity4Limit != null && !severity4Limit.isEmpty()) {
        			int severity4LimitInt = Integer.parseInt(severity4Limit);
        			if(severity4LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckSeverity5Limit(@QueryParameter String severity5Limit) {
        	try {
        		if (severity5Limit != null && !severity5Limit.isEmpty()) {
        			int severity5LimitInt = Integer.parseInt(severity5Limit);
        			if(severity5LimitInt < 0) {
        				return FormValidation.error("Please enter a number greater than or equal to 0.");
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid number!");
        	}
        	return FormValidation.ok();
        }
        
        public FormValidation doCheckQidList(@QueryParameter String qidList) {
        	if (qidList == null || qidList.isEmpty()) {
        		return FormValidation.ok();
        	}
        	try {
        		String[] qidsString = qidList.split(",");
        		for (String qid : qidsString) {
        			if (qid.contains("-")) {
        				String[] range = qid.split("-");
        				int firstInRange = Integer.parseInt(range[0].trim());
        				int lastInRange = Integer.parseInt(range[1].trim());
        				
        				if (firstInRange > lastInRange) {
        					return FormValidation.error("Enter valid QID range");
        				}
        			} else {
       				 int qidInt = Integer.parseInt(qid.trim());
        			}
        		}
        	} catch(Exception e) {
        		return FormValidation.error("Enter valid QID range/numbers");
        	}
        	return FormValidation.ok();
        }
        
        public List<Map<String, String>> getPlatforms() {
        	List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        	for (Map.Entry<String, Map<String, String>> platform : Helper.platformsList.entrySet()) {
                Map<String, String>obj = platform.getValue();
                result.add(obj);
            }
            return result;
        }
    }
    
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws AbortException {
    	listener.getLogger().println("Qualys WASScan task - Started.");
    	Result r = build.getResult();
        String result = r.toString();
        if (result.equals("SUCCESS")) {
	    	if (webAppId != null && !webAppId.isEmpty()) {
	            try {
	            	Item project = build.getProject();
	            	launchWebAppScan(build, listener,  webAppId, project);
	            } catch (Exception e) {
	            	if(e.toString() == "java.lang.Exception") {
	            		throw new AbortException("Exception in Qualys Vulnerabilities scan result. Finishing the build.");
	            	} else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {
	            		logger.log(Level.SEVERE, "Error: User Aborted");
	            		throw new AbortException("User Aborted/Interrupted execution of the build.");
	            	}else {
	            		logger.log(Level.SEVERE, "Error: "+e.getMessage());
	            		e.printStackTrace();
	            		throw new AbortException(e.getMessage());
	            	}
	            } 
	    	}else {
	    	    listener.getLogger().println("No WebApp ID Configured.");
	       		throw new AbortException("WebApp ID can't be set to null or empty.");
	      }
	   }else {
           listener.getLogger().println("Since the build is not successful, will not launch Qualys WAS scan.");
       }
       return true;
    }
    
    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath filePath, @Nonnull Launcher launcher, @Nonnull TaskListener taskListener) throws InterruptedException, IOException {
    	taskListener.getLogger().println("Qualys WASScan task - Started.");
    	if (webAppId != null && !webAppId.isEmpty()) {
             try {
            	 Item project = run.getParent();
            	 launchWebAppScan(run, taskListener,  webAppId, project);
             } catch (Exception e) {
            	 if(e.toString() == "java.lang.Exception") {
	            		throw new AbortException("Exception in Qualys Vulnerabilities scan result. Finishing the build.");
	            	} else if (e.getMessage().equalsIgnoreCase("sleep interrupted")) {
	            		logger.log(Level.SEVERE, "Error: User Aborted");
	            		throw new AbortException("User Aborted/Interrupted execution of the build.");
	            	}else {
		            	 logger.log(Level.SEVERE, "Error: "+e.getMessage());
		            	 e.printStackTrace();
		                 throw new AbortException(e.getMessage());
	            	}
             }
        } else {
        	taskListener.getLogger().println("No WebApp ID Configured.");
        	throw new AbortException("WebApp ID can't be set to null or empty.");
        }
        return;
    }
    
    public void launchWebAppScan(Run<?, ?> run, TaskListener listener, String webAppID, Item project) throws Exception {
    	Map<String, String> platformObj = Helper.platformsList.get(platform);
    	String portalUrl = apiServer;
    	//set apiServer URL according to platform
    	if(!platform.equalsIgnoreCase("pcp")) {
    		setApiServer(platformObj.get("url"));
    		logger.info("Using qualys API Server URL: " + apiServer);
    		portalUrl = platformObj.get("portal");
    	}
    	listener.getLogger().println("Qualys Platform: " + platform +". Using Qualys API server: " + apiServer);
    	String apiUser = "";
    	String apiPass = "";
    	String proxyUsername = "";
    	String proxyPassword = "";
    	try {
			StandardUsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(
					CredentialsProvider.lookupCredentials(
							StandardUsernamePasswordCredentials.class,
							project, ACL.SYSTEM,
							URIRequirementBuilder.fromUri(apiServer).build()),
					CredentialsMatchers.withId(credsId));
			
			if (credential != null) {
				apiUser = credential.getUsername();
				apiPass = credential.getPassword().getPlainText();
				if(apiPass.trim().equals("") || apiUser.trim().equals("")) {
					throw new Exception("Username and/or Password field is empty for credentials id: " + credsId);
				}
			}else {
				throw new Exception("Could not read credentials for credentials id: " + credsId);
			}
		}catch(Exception e){
			e.printStackTrace();
			//buildLogger.println("Inavlid credentials! " + e.getMessage());
			throw new Exception("Inavlid credentials! " + e.getMessage());
		}
    	//test connection first
    	QualysAuth auth = new QualysAuth();
    	auth.setQualysCredentials(apiServer, apiUser, apiPass);
    	if(useProxy) {
    		if (StringUtils.isNotEmpty(proxyCredentialsId)) {
    			StandardUsernamePasswordCredentials credential = CredentialsMatchers.firstOrNull(
    					CredentialsProvider.lookupCredentials(
    							StandardUsernamePasswordCredentials.class,
    							project, ACL.SYSTEM,
    							URIRequirementBuilder.fromUri(apiServer).build()),
    					CredentialsMatchers.withId(proxyCredentialsId));

                proxyUsername = (credential != null ? credential.getUsername() : "");
                proxyPassword = (credential != null ? credential.getPassword().getPlainText() : "");
            }
        	auth.setProxyCredentials(proxyServer, proxyPort, proxyUsername, proxyPassword);
    	}
    	QualysCSClient client = new QualysCSClient(auth, System.out);
    	try {
    		listener.getLogger().println("Testing connection with Qualys API Server...");
    		client.testConnection();
    		listener.getLogger().println("Test connection successful.");
    	}catch(Exception e) {
    		listener.getLogger().println("Test connection failed. Reason: " + e.getMessage());
    		throw new Exception(e.getMessage());
    	}
    	
    	if (webAppID == null || webAppID.isEmpty()) {
         	listener.getLogger().println("No webApp ID configured.");
         	return;
        }
    	boolean isFailConditionsConfigured = false;
    	this.isFailOnSevereVulns = this.isSev1Vulns || this.isSev2Vulns || this.isSev3Vulns || this.isSev4Vulns || this.isSev5Vulns;
    	if(isFailOnQidFound || isFailOnSevereVulns || failOnScanError) {
    		isFailConditionsConfigured = true;
    	}
    	
    	WASScanLauncher launcher = new WASScanLauncher(run, listener, webAppID, scanName, scanType, authRecord, optionProfile, cancelOptions, authRecordId,
        		optionProfileId, cancelHours, isFailConditionsConfigured, pollingInterval, vulnsTimeout, getCriteriaAsJsonObject(), 
        		apiServer, apiUser, apiPass, useProxy, proxyServer, proxyPort, proxyUsername, proxyPassword, portalUrl, failOnScanError);
    	
    	logger.info("Qualys task - Started Launching web app scanning with WAS.");
    	launcher.getAndProcessLaunchScanResult();
        listener.getLogger().println("Qualys task - Finished.");
        logger.info("Qualys task - Finished.");
    }
}
