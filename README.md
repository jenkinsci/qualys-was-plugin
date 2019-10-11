# Qualys WAS(Web Application Security) Plugin

## About

The Qualys WAS Jenkins plugin empowers DevOps teams to build application vulnerability scans into their existing CI/CD processes. By integrating scans in this manner, application security testing is accomplished earlier in the SDLC to catch and eliminate security flaws.

## How this plugin works

When the plugin step starts, it launches a scan on the selected web application with the configured options. Qualys WAS module scans it and responds with findings and Grade score. If you have configured any pass/fail criteria, the plugin evaluates the response against that. If it finds something is not matching your criteria, it will cause exception to fail your build. Otherwise, your build job proceeds to next step (if any).  

## How to use this plugin

### Prerequisites

* A valid Qualys subscription with access to WAS(Web Application Security) module and Qualys APIs.


### Where to use this plugin step

We recommend using this plugin step during "Post-build" phase of your job, right after you deploy your web application. 

### Configuration

If you are using pipeline, you should go to "Pipeline Syntax", and select `qualysWASScan` step.
If you are using freestyle, you should add `qualysWASScan` build step.

A form appears with several input fields. Now you are ready to configure the plugin. 

#### Qualys Credentials

1. Select your Qualys Portal from given dropdown. 
2. Select/Add your Qualys API Credentials.
3. If you need proxy to communicate to the Internet, set correct proxy settings. 
4. To confirm that Jenkins can communicate to Qualys Cloud Platform and APIs, use `Test Connection` button.

#### Web Application to Scan

1. The "Select Web Application from WAS" field lists all the Web apps entries you have made to Qualys WAS module. Select the one for which you are want to scan the web application. *Please note* that, the Web Applications are automatically populated in this dropdown if you have created web application on Qualys UI before. 
2. In "Scan Name" field, provide scan name for the Scan. By default, the WAS scan name will be: [job_name]_jenkins_build_[build_number] + timestamp. You can edit the scan name, but a timestamp will automatically be appended regardless.
3. You can choose to run a Discovery scan or Vulnerability scan. The default is Vulnerability scan.

#### Pass/Fail Criteria

You can set conditions to fail a build by vulnerability severity and Qualys WAS Vulnerability Identifiers (QIDs).

1. Configure to fail a build if the number of detections exceeds the limit specified for one or more severity types and/or if specified QIDs are found in scan results. For example, to fail a build if severity 5 vulnerabilities count is more than 2, select the “Fail with more than severity 5” option and specify 2. 
2. Configure to fail a build if the configured QIDs found in the scan result.

#### Timeout Settings

In the Timeout settings, specify the polling frequency in minutes for collecting the WAS scan status data and the timeout duration for a running scan.

### Genrate Pipeline Script *(for pipeline project only)*

If you are configuring pipeline project, click the `Generate Pipeline Script` button/link. It will give you a command which you can copy and paste in your project's pipeline script. 


