package com.qualys.plugins.wasPlugin.QualysClient;

import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;

import com.qualys.plugins.wasPlugin.QualysAuth.QualysAuth;

class QualysBaseClient {
    private QualysAuth auth;
    protected PrintStream stream;
    protected int timeout = 30; // in seconds

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
    	//builder.loadTrustMaterial(null, (chain, authType) -> true);
    	SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
    	final HttpClientBuilder clientBuilder = HttpClients.custom().setSSLSocketFactory(sslsf);
    	
    	final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
    	
    	clientBuilder.setDefaultRequestConfig(config);
    	clientBuilder.setDefaultCredentialsProvider(credentialsProvider);    	
    	
    	if(this.auth.getProxyServer() != null && !this.auth.getProxyServer().isEmpty()) { 
    		final HttpHost proxyHost = new HttpHost(this.auth.getProxyServer(),this.auth.getProxyPort()); 	
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
     * This method use to set connection timeout for http client.   
     * @param timeout - int - in secs
     */
    public void setTimeout(int timeout) {
    	this.timeout = timeout;    	
    }
}
