function showVulnsTable(scanResult){
	var vulns = scanResult.vulnsTable.list;
	//Vulns Table
	var table = jQuery('#vulnsTable').DataTable({             
		"autoWidth": false, 
		"language": {
    		"emptyTable": "No vulnerabilities found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[
            { "mData": "WasScanVuln.qid", sDefaultContent :  '', "width": "8%"},
            { "mData": "WasScanVuln.title", sDefaultContent :  '', "width": "35%"},
            { "mData": "WasScanVuln.uri", sDefaultContent :  '', "width": "50%"},
            { "mData": "WasScanVuln.instances", sDefaultContent :  '', "width": "10%"}
        ],
        'aoColumnDefs': [
        	{ "sTitle": "QID", "aTargets": [0]},
            { "sTitle": "Title", "aTargets": [1] },    
            { "sTitle": "URL", "aTargets": [2] },
            { "sTitle": "Available Unauthenticated?", "aTargets": [3],
            	"render":  function ( data, type, row ) {
        			var list = data.list;
        			var auth = "No";
        			if(list != null) {
        				list.forEach(function(val){
        					if(val.WasScanVulnInstance.authenticated == "false") auth = "Yes";
        				});
        			}
            		return auth;
    			}
            }
        ]
    });
}

function showEvaluationSummary(scanResult){
	var isEvaluationResult = scanResult.isEvaluationResult;
	if(isEvaluationResult === 1){
		var reportObject = scanResult.evaluationResult;
		if(reportObject.qids){
			if(reportObject.qids.configured){
				jQuery("#qid-found .image-scan-status").removeClass("not-configured").addClass(reportObject.qids.result ? "ok" : "fail");
				jQuery("#qid-found .image-scan-status .tooltip-text").html("<b>configured:</b> "+reportObject.qids.configured + "<br /><b>Found: </b>"+ (reportObject.qids.found ? reportObject.qids.found : "None"));
			}
		}
		if(reportObject.severities){
			var severityObj = reportObject["severities"];
			for(var i=1; i<6; i++){
				if(severityObj[i])
					if(!(severityObj[i].configured === null || severityObj[i].configured === -1)){
						jQuery("#sev" + i + "-found .image-scan-status").removeClass("not-configured").addClass(severityObj[i].result ? "ok" : "fail");
						jQuery("#sev" + i + "-found .image-scan-status .tooltip-text").html("<b>configured:</b> more than "+severityObj[i].configured + "<br /><b>Found: </b>"+ (severityObj[i].found !== null ? severityObj[i].found : "0"));
					}
			}
		}
	}
}

function drawVulnsCharts(scanResults){
	jQuery("#sevVulns-error").hide();
	jQuery("#sevVulns").show();
	jQuery("#pie-legend-div").show();
	if(scanResults.vulns == "0"){
		jQuery("#sevVulns").hide();
		jQuery("#pie-legend-div").hide();
		jQuery("#sevVulns-error").show();
	}else{
		var d = scanResults.vulnsBySeverity;
		//var d = {"1": 12,"2": 1,"3": 32,"4": 5,"5": 15}
		var count = Array();
		var severity = Array();
		
		var i = 0;
		var total = 0;
		for (var key in d) {
			count[i] = d[key];
		   severity[i] = key;
		   total += count[i]; 
		   i++;
		}
		var options = {
		    //segmentShowStroke: false,
		    animateRotate: true,
		    animateScale: false,
		    percentageInnerCutout: 50,
		    tooltipTemplate: "<%= label %>"
		}
		var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
		var labels = count; 
		jQuery("#confTotCount").text(total);
		if(! count.some(el => el !== 0)){
			count = ["1", "1", "1", "1", "1"];
			severity = ["1", "2", "3", "4", "5"];
			labels = ["0", "0", "0", "0", "0"];	
			colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		}
		
		var c = jQuery("#sevVulns").get(0);
			var ctx = c.getContext("2d");
		
			var pieData = [
				{
				value: count[4].toString(),
				label: "Sev " + severity[4].toString() + " (" + labels[4] + ")",
				color: colors[4]
				},
				{
				value: count[3].toString(),
				label: "Sev " + severity[3].toString() + " (" + labels[3] + ")",
				color: colors[3]
				},
				{
				value: count[2].toString(),
				label: "Sev " + severity[2].toString() + " (" + labels[2] + ")",
				color: colors[2]
				},
				{
				value: count[1].toString(),
				label: "Sev " + severity[1].toString() + " (" + labels[1] + ")",
				color: colors[1]
				},
				{
				value: count[0].toString(),
				label: "Sev " + severity[0].toString() + " (" + labels[0] + ")",
				color: colors[0]
				}
			];
			
			var chart = new Chart(ctx).Doughnut(pieData,options);		
		jQuery("#pie-legend-div").append(chart.generateLegend());
	}
}