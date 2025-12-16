package com.qualys.plugins.wasPlugin.QualysAuth;

import hudson.util.Secret;

public class QualysAuth {
    private AuthType authType;
    private String server;
    private String username;
    private Secret password;
    private String authKey;
    private String proxyServer;
    private String proxyUsername;
    private Secret proxyPassword;
    private int proxyPort;
    private String clientId;
    private String clientSecret;

    public QualysAuth () {
        
    }

    public QualysAuth (String server, String oauthKey) {
        this.authKey = oauthKey;
    }

    public AuthType getAuthType() {
        return authType;
    }
    public String getServer() {
        return server;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password.getPlainText();
    }
    
    public String getProxyServer() {
        return proxyServer;
    }

    public String getProxyUsername() {
        return proxyUsername;
    }

    public String getProxyPassword() {
        return proxyPassword.getPlainText();
    }
    public int getProxyPort() {
        return proxyPort;
    }
    public String getAuthKey() {
        return authKey;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

   
    public void setQualysCredentials(String server, String username, String password) {
    	this.server = server;
        this.username = username;
        this.password = Secret.fromString(password);
    }

    public void setQualysCredentials(String server, AuthType authType, String username, String password, String clientId, String clientSecret) {
        this.authType = authType;
        this.server = server;
        this.username = username;
        this.password = Secret.fromString(password);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }
    public void setProxyCredentials(String proxyServer, int proxyPort, String proxyUsername, String proxyPassword) {
    	this.proxyServer = proxyServer;
        this.proxyUsername = proxyUsername;
        this.proxyPassword = Secret.fromString(proxyPassword);
        this.proxyPort = proxyPort;
    }

}
