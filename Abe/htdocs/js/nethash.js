// Copyright(C) 2013 by Abe developers.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <http://www.gnu.org/licenses/agpl.html>.

"use strict";
$(document).ready(function() {
/* Set the defaults for DataTables initialisation */
$.extend( true, $.fn.dataTable.defaults, {
	"sDom": "<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>",
	"sPaginationType": "bootstrap",
	"oLanguage": {
		"sLengthMenu": "_MENU_ records per page"
	}
} );


/* Default class modification */
$.extend( $.fn.dataTableExt.oStdClasses, {
	"sWrapper": "dataTables_wrapper form-inline"
} );


/* API method to get paging information */
$.fn.dataTableExt.oApi.fnPagingInfo = function ( oSettings )
{
	return {
		"iStart":         oSettings._iDisplayStart,
		"iEnd":           oSettings.fnDisplayEnd(),
		"iLength":        oSettings._iDisplayLength,
		"iTotal":         oSettings.fnRecordsTotal(),
		"iFilteredTotal": oSettings.fnRecordsDisplay(),
		"iPage":          oSettings._iDisplayLength === -1 ?
			0 : Math.ceil( oSettings._iDisplayStart / oSettings._iDisplayLength ),
		"iTotalPages":    oSettings._iDisplayLength === -1 ?
			0 : Math.ceil( oSettings.fnRecordsDisplay() / oSettings._iDisplayLength )
	};
};


/* Bootstrap style pagination control */
$.extend( $.fn.dataTableExt.oPagination, {
	"bootstrap": {
		"fnInit": function( oSettings, nPaging, fnDraw ) {
			var oLang = oSettings.oLanguage.oPaginate;
			var fnClickHandler = function ( e ) {
				e.preventDefault();
				if ( oSettings.oApi._fnPageChange(oSettings, e.data.action) ) {
					fnDraw( oSettings );
				}
			};

			$(nPaging).append(
				'<ul class="pagination">'+
					'<li class="prev disabled"><a href="#">&larr; '+oLang.sPrevious+'</a></li>'+
					'<li class="next disabled"><a href="#">'+oLang.sNext+' &rarr; </a></li>'+
				'</ul>'
			);
			var els = $('a', nPaging);
			$(els[0]).bind( 'click.DT', { action: "previous" }, fnClickHandler );
			$(els[1]).bind( 'click.DT', { action: "next" }, fnClickHandler );
		},

		"fnUpdate": function ( oSettings, fnDraw ) {
			var iListLength = 5;
			var oPaging = oSettings.oInstance.fnPagingInfo();
			var an = oSettings.aanFeatures.p;
			var i, ien, j, sClass, iStart, iEnd, iHalf=Math.floor(iListLength/2);

			if ( oPaging.iTotalPages < iListLength) {
				iStart = 1;
				iEnd = oPaging.iTotalPages;
			}
			else if ( oPaging.iPage <= iHalf ) {
				iStart = 1;
				iEnd = iListLength;
			} else if ( oPaging.iPage >= (oPaging.iTotalPages-iHalf) ) {
				iStart = oPaging.iTotalPages - iListLength + 1;
				iEnd = oPaging.iTotalPages;
			} else {
				iStart = oPaging.iPage - iHalf + 1;
				iEnd = iStart + iListLength - 1;
			}

			for ( i=0, ien=an.length ; i<ien ; i++ ) {
				// Remove the middle elements
				$('li:gt(0)', an[i]).filter(':not(:last)').remove();

				// Add the new list items and their event handlers
				for ( j=iStart ; j<=iEnd ; j++ ) {
					sClass = (j==oPaging.iPage+1) ? 'class="active"' : '';
					$('<li '+sClass+'><a href="#">'+j+'</a></li>')
						.insertBefore( $('li:last', an[i])[0] )
						.bind('click', function (e) {
							e.preventDefault();
							oSettings._iDisplayStart = (parseInt($('a', this).text(),10)-1) * oPaging.iLength;
							fnDraw( oSettings );
						} );
				}

				// Add / remove disabled classes from the static elements
				if ( oPaging.iPage === 0 ) {
					$('li:first', an[i]).addClass('disabled');
				} else {
					$('li:first', an[i]).removeClass('disabled');
				}

				if ( oPaging.iPage === oPaging.iTotalPages-1 || oPaging.iTotalPages === 0 ) {
					$('li:last', an[i]).addClass('disabled');
				} else {
					$('li:last', an[i]).removeClass('disabled');
				}
			}
		}
	}
} );


/*
 * TableTools Bootstrap compatibility
 * Required TableTools 2.1+
 */
if ( $.fn.DataTable.TableTools ) {
	// Set the classes that TableTools uses to something suitable for Bootstrap
	$.extend( true, $.fn.DataTable.TableTools.classes, {
		"container": "DTTT btn-group",
		"buttons": {
			"normal": "btn",
			"disabled": "disabled"
		},
		"collection": {
			"container": "DTTT_dropdown dropdown-menu",
			"buttons": {
				"normal": "",
				"disabled": "disabled"
			}
		},
		"print": {
			"info": "DTTT_print_info modal"
		},
		"select": {
			"row": "active"
		}
	} );

	// Have the collection use a bootstrap compatible dropdown
	$.extend( true, $.fn.DataTable.TableTools.DEFAULTS.oTags, {
		"collection": {
			"container": "ul",
			"button": "li",
			"liner": "a"
		}
	} );
}
$.fn.dataTableExt.oApi.fnReloadAjax = function ( oSettings, sNewSource, fnCallback, bStandingRedraw )
{
    // DataTables 1.10 compatibility - if 1.10 then versionCheck exists.
    // 1.10s API has ajax reloading built in, so we use those abilities
    // directly.
    if ( $.fn.dataTable.versionCheck ) {
        var api = new $.fn.dataTable.Api( oSettings );
 
        if ( sNewSource ) {
            api.ajax.url( sNewSource ).load( fnCallback, !bStandingRedraw );
        }
        else {
            api.ajax.reload( fnCallback, !bStandingRedraw );
        }
        return;
    }
 
    if ( sNewSource !== undefined && sNewSource !== null ) {
        oSettings.sAjaxSource = sNewSource;
    }
 
    // Server-side processing should just call fnDraw
    if ( oSettings.oFeatures.bServerSide ) {
        this.fnDraw();
        return;
    }
 
    this.oApi._fnProcessingDisplay( oSettings, true );
    var that = this;
    var iStart = oSettings._iDisplayStart;
    var aData = [];
 
    this.oApi._fnServerParams( oSettings, aData );
 
    oSettings.fnServerData.call( oSettings.oInstance, oSettings.sAjaxSource, aData, function(json) {
        /* Clear the old information from the table */
        that.oApi._fnClearTable( oSettings );
 
        /* Got the data - add it to the table */
        var aData =  (oSettings.sAjaxDataProp !== "") ?
            that.oApi._fnGetObjectDataFn( oSettings.sAjaxDataProp )( json ) : json;
 
        for ( var i=0 ; i<aData.length ; i++ )
        {
            that.oApi._fnAddData( oSettings, aData[i] );
        }
         
        oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
 
        that.fnDraw();
 
        if ( bStandingRedraw === true )
        {
            oSettings._iDisplayStart = iStart;
            that.oApi._fnCalculateEnd( oSettings );
            that.fnDraw( false );
        }
 
        that.oApi._fnProcessingDisplay( oSettings, false );
 
        /* Callback user function - for event handlers etc */
        if ( typeof fnCallback == 'function' && fnCallback !== null )
        {
            fnCallback( oSettings );
        }
    }, oSettings );
};
if( typeof block_data_url !== "undefined" ){
		 $('#chain').dataTable( {
					"bFilter": false,
					"sDom": "<'row'<'col-lg-6'l><'col-lg-6'p>r>t<'row'<'col-lg-6'l><'col-lg-6'p>>",
					"sPaginationType": "bootstrap",
					"oLanguage": {
						"sLengthMenu": "Display _MENU_ blocks per page",
                        "sProcessing": ""
					},
					"aoColumnDefs": [{ "bVisible": false, "aTargets": [ 1 ] }],
                    "bInfo": false,
                    "bSort": false,
                    "bProcessing": true,
                    "bServerSide": true,
					"sAjaxSource": block_data_url,
					"fnRowCallback": function( nRow, aData, iDisplayIndex ) {
                        $(nRow).find("td:first").html('<a href="/block/' + aData[1] + '">' + aData[0] + '</a>');
                    },
					"sServerMethod": "POST"
					
                    
		} );
		$(".dataTables_length select").addClass("form-control");
}
if( typeof latest_transactions_url !== "undefined" ){
	var tx_Table = $('#txs').dataTable( {
					"bFilter": false,
					"sDom": "t",
					"bInfo": false,
                    "bSort": false,
                    "bProcessing": false,
					"aoColumnDefs": [{ "bVisible": false, "aTargets": [ 1 ] }],
                    "bServerSide": false,
					"sAjaxSource": latest_transactions_url,
					"fnRowCallback": function( nRow, aData, iDisplayIndex ) {
                        $(nRow).find("td:first").html('<a href="/tx/' + aData[1] + '">' + aData[0] + '</a>');
                    },
	});
	window.setInterval(function(){tx_Table.fnReloadAjax(); }, 10000);
}

			} );
var Abe = (function() {

    var SVG_NS = "http://www.w3.org/2000/svg";
    var ABE_NS = "http://abe.bit/abe";

    function draw(svg, interval) {
        var i, elts, node, windows, chart, lines, rows, work, first;
        var elapsed, worked, drawn, height, matrix;
        var hi = -Infinity, lo = Infinity;

        if (interval === undefined) {
            interval = 24*60*60;   // 1 day
        }

        elts = svg.getElementsByTagNameNS(ABE_NS, "*");

        // In inline SVG (FF 18.0) the above search returns empty.
        // Here is a workaround.
        if (elts.length === 0) {
            elts = [];
            Array.prototype.forEach.call(
                svg.getElementsByTagName("*"),
                function(elt) {
                    if (elt.localName.indexOf("abe:") === 0)
                        elts.push(elt);
                });
        }

        rows = [];

        for (i = 0; i < elts.length; i++) {
            node = elts[i];
            switch (node.localName.replace("abe:", "")) {
            case "nethash":
                rows.push(nodeToRow(node));
                break;
            }
        }

        if (rows.length < 2) {
            alert("Not enough data to chart!");
            return;
        }

        rows[0].work = 0;  // clobber bogus value

        for (i = 1, work = 0; i < rows.length; i++) {
            work += rows[i].work;

            if (rows[i].nTime > rows[0].nTime) {
                first = work / (rows[i].nTime - rows[0].nTime);
                break;
            }
        }

        if (first === undefined) {
            alert("Can not make chart: block times do not increase!");
            return;
        }

        function make_point(x, value) {
            var point = svg.createSVGPoint();
            point.x = x
            point.y = value;
            if (value < lo) lo = value;
            if (value > hi) hi = value;
            return point;
        }

        function parse_window(s) {
            var m = /^(\d*(?:\.\d+)?)(d|days?)$/i.exec(s);
            var n;

            if (m) {
                n = Number(m[1]);
                if (n > 0) {
                    switch (m[2].toLowerCase()) {
                    case "d": case "day": case "days": return n * 24*60*60;
                    default: break;
                    }
                }
            }

            throw "Can not parse interval: " + s;
        }

        function make_line(elt) {
            var line = { elt: elt };
            elt.points.initialize(make_point(0, Math.log(first)));
            line.window = parse_window(elt.getAttributeNS(ABE_NS, "window"));
            line.rate = first;
            line.oldShare = 1 / Math.exp(interval / line.window);
            line.newShare = 1 - line.oldShare;
            return line;
        }

        chart = svg.getElementById("chart");
        lines = Array.prototype.map.call(chart.getElementsByTagName("polyline"),
                                         make_line)
        rows.sort(function(a, b) { return a.nTime - b.nTime; });
        elapsed = 0;
        worked = 0;
        drawn = 0;

        function extend_line(line) {
            line.rate *= line.oldShare;
            line.rate += line.newShare * worked / interval;
            if (line.rate > 0)
                line.elt.points.appendItem(make_point(drawn,
                                                      Math.log(line.rate)));
        }

        function tick(seconds, work) {

            elapsed += seconds;

            while (elapsed >= interval) {
                drawn++;
                lines.forEach(extend_line);
                elapsed -= interval;
                worked = 0;
            }

            worked += work;
        }

        for (i = 1; i < rows.length; i++) {
            tick(rows[i].nTime - rows[i-1].nTime, rows[i].work);
        }

        matrix = svg.createSVGMatrix();
        matrix.a = 1 / drawn;

        if (lo !== hi) {
            height = svg.viewBox.baseVal.height;
            matrix.d = height / 1.1 / (lo - hi);
            matrix.f = height / 1.05 - lo * matrix.d;
            //matrix.f = 1 + lo / (hi - lo);
        }

        chart.transform.baseVal.initialize(
            chart.transform.baseVal.createSVGTransformFromMatrix(matrix));
    }

    function nodeToRow(node) {
        return {
            nTime:      Number(node.getAttributeNS(null, "t")),
            difficulty: Number(node.getAttributeNS(null, "d")),
            work:       Number(node.getAttributeNS(null, "w"))
        };
    }

    return { draw: draw };
})();
