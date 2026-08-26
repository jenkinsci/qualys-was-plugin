package com.qualys.plugins.wasPlugin.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;


public class OIDCCredential extends BaseStandardCredentials {

    private final String clientId;
    private final Secret clientSecret;
    private final String tokenUrl;
    private final String oidcScope;
    private final String audience;

    @DataBoundConstructor
    public OIDCCredential(CredentialsScope scope, String id, String description,
                          String clientId, String clientSecret, String tokenUrl, 
                          String oidcScope, String audience) {
        super(scope, id, description);
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.tokenUrl = tokenUrl;
        this.oidcScope = oidcScope;
        this.audience = audience;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return Secret.toString(clientSecret);
    }

    public String getTokenUrl() {
        return tokenUrl;
    }

    public String getOidcScope() {
        return oidcScope;
    }

    public String getAudience() {
        return audience;
    }

    @Extension
    @Symbol("qualysOIDCCredential_was")
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Qualys WAS IDP Credential";
        }

        // Expose scopes to Jelly
        public CredentialsScope[] getAvailableScopes() {
            return CredentialsScope.values();
        }

        @POST
        public FormValidation doCheckClientId(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Client ID cannot be empty");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckClientSecret(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Client Secret cannot be empty");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckTokenUrl(@QueryParameter String value) {
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Token URL cannot be empty");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckOidcScope(@QueryParameter String value) {
            return FormValidation.ok();
        }
    }

}
