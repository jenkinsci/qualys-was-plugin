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
            {
                "className": 'details-control',
                "orderable": false,
                "data": null,
                "defaultContent": ''
            },
            { "mData": "WasScanVuln.qid", sDefaultContent :  '', "width": "7%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.severity", sDefaultContent :  '', "width": "2%"},
            { "mData": "WasScanVuln.title", sDefaultContent :  '', "width": "15%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.severity", sDefaultContent :  '', "width": "10%", "className": "center"},
            { "mData": "WasScanVuln.uri", sDefaultContent :  '', "width": "20%", "className": "dt-head-left"},
            { "mData": "WasScanVuln.instances", sDefaultContent :  '', "width": "15%", "className": "center"}

        ],
        'aoColumnDefs': [
            { "sTitle": "", "aTargets": [0] },
            { "sTitle": "QID", "aTargets": [1], "className": "text-left"},
        	{ "sTitle": "", "aTargets": [2],
            	"render":  function ( data, type, row ) {
        			var sev = parseInt(data);
        			var reportObject = scanResult.evaluationResult;
        			if(reportObject && reportObject.severities)
        			{
						var severityObj = reportObject["severities"];
						for(var i=1; i<6; i++)
						{
							if(severityObj && severityObj[i])
							{
								if(severityObj[i].configured != null && severityObj[i].configured > -1 && severityObj[i].result != undefined && severityObj[i].result!= null)
								{
									if(sev==i && severityObj[i].result == false )
									{
										return '<img src="/plugin/qualys-was/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

									}

								}
							}
						}
    			    }
    			    if(reportObject && reportObject.qids)
    			    {
    			    	var configuredQids = reportObject["qids"].configured;
    			    	if(configuredQids && configuredQids.length > 0)
    			    	{
    			    		if(configuredQids.indexOf(row.WasScanVuln.qid) != -1)
    			    		{
    			    			return '<img src="/plugin/qualys-was/images/fail.png" height="10" width="10"/><span style="display:none;">breaking</span>';

    			    		}
    			    	}
    			    }
            	}
            },
      
            { "sTitle": "Title", "aTargets": [3], "className": "text-left" },
            { "sTitle": "Severity", "aTargets": [4],"className": "text-left" },
            { "sTitle": "URL", "aTargets": [5], "className": "text-left" },
            { "sTitle": "Available Unauthenticated?", "aTargets": [6],"className": "text-left",
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
    
    jQuery(".custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + 
	    	'<span class="sev-filter-label" >Severity </span>' + 
	    	'<select class="severity-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="5"> 5 </option>' +
	    	'<option value="4"> 4 </option>' +
	    	'<option value="3"> 3 </option>' +
	    	'<option value="2"> 2 </option>' +
	    	'<option value="1"> 1 </option>' +
	    	'</select>' +
	    	'</div>'+
	    	'<ul class="filters-list">' +
    		'<li><input class="custom-filter-checkbox" type="checkbox" id="breakingVulns" value="breakingVulns"><label for="breakingVulns" class="checkbox-title" > Breaking Vulnerabilities </li>' +
    		'</ul>' +
    		'<button type="button" id="reset" >Reset Filters</button>'
	    );
    
     jQuery('.severity-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(4).search( valueSelected ).draw();
	    });
    
     jQuery(".custom-filter-checkbox").on("change", function(e){
		switch(this.value){	
			case 'breakingVulns': 
						var value = (this.checked)? 'breaking' : '';
						table.columns(1).search( value ).draw();
						break;
		}
	});
    
    $( "#reset" ).click(function() 
	{
  		$(".severity-dropdown").val('');
  		$("#breakingVulns").prop("checked",false);
  		table.search( '' ).columns().search( '' ).draw();
	});

	    jQuery('#vulnsTable tbody').on('click', 'td', function () {
            var tr = jQuery(this).closest('tr');
            var row = table.row( tr );

            if ( row.child.isShown() ) {
                // This row is already open - close it
                row.child.hide();
                tr.removeClass('shown');
            }
            else {
                // Open this row
                row.child( format(row.data()) ).show();
                tr.addClass('shown');
            }
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

function format ( d ) {
    var solution = (d.WasScanVuln.solution?d.WasScanVuln.solution:'NotFound');
    var diagnosis = (d.WasScanVuln.diagnosis?d.WasScanVuln.diagnosis:'Not Found');
    return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
	    '<tr>'+
	    	'<td><b>Solution:</b> '+solution+'</td>'+
	    '</tr>'+
        '<tr>'+
	    	'<td><b>Diagnosis:</b> '+ diagnosis +'</td>'+
	    '</tr>'
    '</table>';
}