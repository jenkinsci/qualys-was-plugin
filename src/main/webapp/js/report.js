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
            { "mData": "WasScanVuln.qid", sDefaultContent :  '', "width": "10%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.title", sDefaultContent :  '', "width": "30%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.severity", sDefaultContent :  '', "width": "10%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.uri", sDefaultContent :  '', "width": "40%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.instances", sDefaultContent :  '', "width": "10%", "className": "dt-head-left"}

        ],
        'aoColumnDefs': [
        	{ "sTitle": "QID", "aTargets": [0], "className": "text-left"},
            { "sTitle": "Title", "aTargets": [1], "className": "text-left" },    
             { "sTitle": "Severity", "aTargets": [2],"className": "text-left" },    
            { "sTitle": "URL", "aTargets": [3], "className": "text-left" },
            { "sTitle": "Available Unauthenticated?", "aTargets": [4],"className": "text-left",
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
	 var show_tooltip = true;
    var count = Array();
    var severity = Array();
   	var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A", "#D61E1C"];
    var c = jQuery("#sevVulns").get(0);
    var ctx = c.getContext("2d");

    jQuery("#sevVulns-error").hide();
    jQuery("#sevVulns").show();
    jQuery("#pie-legend-div").show();

    if (scanResults.vulns == "0") {
        jQuery("#sevVulns").hide();
        jQuery("#pie-legend-div").hide();
        jQuery("#sevVulns-error").show();
    } else {
        var d = scanResults.vulnsBySeverity;
        var i = 0;
        var total = 0;

        for (var key in d) {
            count[i] = d[key];
            severity[i] = key;
            total += count[i];
            i++;
        }

        var labels = count;
        
        if (!count.some(el => el !== 0)) {
            count = ["1", "1", "1", "1", "1"];
            severity = ["1", "2", "3", "4", "5"];
            labels = ["0", "0", "0", "0", "0"];
            colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
            show_tooltip = false;
        }

        var options = {
            responsive: true,
            plugins: {
                legend: {
                    display: true,
                    position: 'right'
                },
                tooltip: {
                    enabled: show_tooltip,
                    callbacks: {
                        label: function(context) {
                            var label = context.label;
                            return label;

                        }
                    }
                }
            }
        };

        var pieData = {
            "datasets": [{

                "data": count,
                "backgroundColor": colors
            }],

            // These labels appear in the legend and in the tooltips when hovering different arcs
            "labels": [
                "Sev " + severity[0].toString() + " : " + labels[0],
                "Sev " + severity[1].toString() + " : " + labels[1],
                "Sev " + severity[2].toString() + " : " + labels[2],
                "Sev " + severity[3].toString() + " : " + labels[3],
                "Sev " + severity[4].toString() + " : " + labels[4]
            ]

        };

        jQuery("#confTotCount").text(total);

       new Chart(ctx, {
            "type": "doughnut",
            "data": pieData,
            "options": options
        });
    }
}