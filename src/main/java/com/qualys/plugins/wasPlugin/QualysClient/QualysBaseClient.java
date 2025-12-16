package com.qualys.plugins.wasPlugin.QualysClient;

import java.io.*;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.qualys.plugins.wasPlugin.util.Helper;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

class QualysBaseClient {
    private QualysAuth auth;
    protected PrintStream stream;
    protected int timeout = 30; // in seconds
    private static final String oAuthEndpoint = "/auth/oidc";
    public QualysBaseClient (QualysAuth auth) {
        this.auth = auth;
        this.stream = System.out;
    }

    public QualysBaseClient(QualysAuth auth, PrintStream stream) {
        this.auth = auth;
        this.stream = stream;
    }

    public URL getAbsoluteUrl(String path) throws MalformedURLException {
        path = (path.startsWith("/")) ? path : ("/" + path);
        URL url = new URL(this.auth.getServer() + path);
        return url;
    }

    protected String getBasicAuthHeader() {
        String userPass = this.auth.getUsername() + ":" + this.auth.getPassword();
        String encoded = Base64.getEncoder().encodeToString((userPass).getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    protected CloseableHttpClient getHttpClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

    	RequestConfig config = RequestConfig.custom()
  	    	  .setConnectTimeout(this.timeout * 1000)
  	    	  .setConnectionRequestTimeout(this.timeout * 1000)
  	    	  .setSocketTimeout(this.timeout * 1000).build(); // Timeout settings
    	SSLContextBuilder builder = new SSLContextBuilder();
    	SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
    	final HttpClientBuilder clientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);

    	final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();

    	clientBuilder.setDefaultRequestConfig(config);
        clientBuilder.setDefaultCredentialsProvider(credentialsProvider);

        if (this.auth.getProxyServer() != null && !this.auth.getProxyServer().isEmpty()) {
            final HttpHost proxyHost = new HttpHost(this.auth.getProxyServer(), this.auth.getProxyPort());
    		final HttpRoutePlanner routePlanner = new DefaultProxyRoutePlanner(proxyHost);
    		clientBuilder.setRoutePlanner(routePlanner);

    		String username = this.auth.getProxyUsername();
            String password = this.auth.getProxyPassword();

            if (username != null && !"".equals(username.trim())) {
                System.out.println("Using proxy authentication (user=" + username + ")");
                credentialsProvider.setCredentials(new AuthScope(proxyHost),
                								   new UsernamePasswordCredentials(username, password));
            }

    	}

    	return clientBuilder.build();
    }

    /**
     * Executes a GET request using Apache HttpClient.
     *
     * @param httpClient the HttpClient instance
     * @param url        the target URL
     * @param headers    optional headers (can be null)
     * @return the response body as a String
     * @throws IOException if an error occurs during the request
     */
    protected String sendGetRequest(CloseableHttpClient httpClient, String url, Map<String, String> headers) throws IOException {
        HttpGet getRequest = new HttpGet(url);
        if (headers != null) {
            headers.forEach(getRequest::addHeader);
        }
        try (CloseableHttpResponse response = httpClient.execute(getRequest)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            if (statusCode >= 200 && statusCode < 300) {
                return responseBody;
            } else {
                throw new IOException("GET request failed with status code " + statusCode + ": " + responseBody);
            }
        }
    }

    /**
     * Executes a POST request using Apache HttpClient.
     *
     * @param httpClient the HttpClient instance
     * @param url        the target URL
     * @param headers    optional headers (can be null)
     * @param body       the request body (JSON, form data, etc.)
     * @return the response body as a String
     * @throws IOException if an error occurs during the request
     */
    protected String sendPostRequest(CloseableHttpClient httpClient, String url, Map<String, String> headers, String body) throws IOException {
        HttpPost postRequest = new HttpPost(url);
        if (headers != null) {
            headers.forEach(postRequest::addHeader);
        }
        if (body != null && !body.isEmpty()) {
            postRequest.setEntity(new StringEntity(body));
        }
        try (CloseableHttpResponse response = httpClient.execute(postRequest)) {
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());
            if (statusCode >= 200 && statusCode < 300) {
                return responseBody;
            } else {
                return null;
            }
        }
    }

    /**
     * This method use to set connection timeout for http client.
     * @param timeout - int - in secs
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    protected String getAuthorizationHeader() {

        if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("BASIC"))
            return "Basic " + this.getBasicAuthHeader();
        else if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OAUTH")) {
            return "Bearer " + this.generateJwtTokenUsingClientIdAndClientSecret();
        } else
            return null;
    }

    protected Map<String, String> getOauthHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("accept", "application/json");
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("clientId", this.auth.getClientId());
        headers.put("clientSecret", this.auth.getClientSecret());
        return headers;

    }

    protected Map<String, String> getCommonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("accept", "application/json");
        headers.put("Authorization", this.getAuthorizationHeader());
        if (String.valueOf(this.auth.getAuthType()).equalsIgnoreCase("OAUTH"))
            headers.put("request-source", "gateway");
        return headers;
    }

    public String generateJwtTokenUsingClientIdAndClientSecret() {
        String apiUrl = Helper.getGatewayUrl(auth.getServer()) + oAuthEndpoint;
        System.out.println("Requesting new auth token using clientId and clientSecret from API Gateway Server:" + apiUrl);
        CloseableHttpClient httpClient = null;
        try {
            httpClient = getHttpClient();
            String response = this.sendPostRequest(httpClient, apiUrl, this.getOauthHeaders(), null);

            if (response != null) {
                System.out.println("Successfully received auth token from API Gateway Server.");
                return response;
            } else
                System.out.println("Error while generating JWT token.");
        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            System.out.println("Error while generating JWT token " + e.getMessage());
        }

        return null;

    }
}


