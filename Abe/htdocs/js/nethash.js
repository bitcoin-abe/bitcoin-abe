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

var Abe = (function() {

    var SVG_NS = "http://www.w3.org/2000/svg";
    var ABE_NS = "http://abe.bit/abe";

    function draw(svg, opts) {
        var i, elts, node, windows, chart, lines, rows, work, first;
        var elapsed, worked, drawn, width, height, intervals, matrix;
        var difficulty_rate, chart_transform, time_end;
        opts = opts || {};
        var grain = opts.granularity, sawtooth = opts.sawtooth;
        var hi = -Infinity, lo = Infinity;

        if (grain === undefined) {
            grain = 6*60*60;   // 6 hours
            grain = 60*60;   // 1 hour
	    grain = 1;
            grain = 24*60*60;   // 1 day
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

        function make_point(x, value) {
            var point = svg.createSVGPoint();
            point.x = x
            point.y = value;
            if (value < lo) lo = value;
            if (value > hi) hi = value;
            return point;
        }

        function parse_interval(s) {
            var m, n;

            m = /^(\d*(?:\.\d+)?)(d|days?|h|hours?|m|s)$/i.exec(s);

            if (m) {
                n = Number(m[1]);
                if (n > 0) {
                    switch (m[2].toLowerCase()) {
                    case "d": case "day": case "days": return n * 24*60*60;
                    case "h": case "hour": case "hours": return n * 60*60;
                    case "m": return n * 60;
                    case "s": return n;
                    default: break;
                    }
                }
            }

            throw "Can not parse interval: " + s;
        }

        function scale_rate(rate) {
            return Math.log(rate);
        }

        function make_line(elt) {
            var line = { elt: elt }, window;

            window = elt.getAttributeNS(ABE_NS, "window");

            if (window) {
                line.oldShare = 1 / Math.exp(grain / parse_interval(window));
                line.newShare = 1 - line.oldShare;
            }
            else {
                line.block_time = Number(
                    elt.getAttributeNS(ABE_NS, "block-time"));

                if (line.block_time <= 0) {
                    throw "Invalid block_time for difficulty line: " +
                        line.block_time;
                }

                difficulty_rate = rows[0].difficulty / line.block_time;
                line.rate = difficulty_rate;
            }

            return line;
        }

        chart = svg.getElementById("chart");
        lines = Array.prototype.map.call(chart.getElementsByTagName("polyline"),
                                         make_line)
        first = difficulty_rate;

        if (first === undefined) {
            for (i = 0, work = 0; i < rows.length; i++) {
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
        }

        function init_line(line) {
            line.rate = first;
            line.elt.points.initialize(make_point(0, scale_rate(line.rate)));
        }
        lines.forEach(init_line);

        rows.sort(function(a, b) { return a.nTime - b.nTime; });
        intervals = Math.ceil((rows[rows.length-1].nTime - rows[0].nTime) /
                              grain);
        // XXX Should use the chart element's dimensions, not <svg>.
        width = svg.viewBox.baseVal.width;
        height = svg.viewBox.baseVal.height;
        elapsed = 0;
        worked = 0;
        drawn = 0;

        function tick(seconds, work) {

            elapsed += seconds;

	    var count = Math.floor(elapsed / grain);

	    function extend_line(line) {
		var old_rate;

		if (line.block_time) {
		    old_rate = line.rate;
		    line.rate = rows[i].difficulty / line.block_time;

		    if (line.rate === old_rate) {
			return;
		    }
		}
		else {
		    line.rate *= Math.pow(line.oldShare, count);
		    if (worked === 0) {
			return;
		    }
		    old_rate = sawtooth ? line.rate : 0;
		    line.rate += line.newShare * worked / grain;
		}
		if (old_rate > 0) {
		    line.elt.points.appendItem(
                        make_point(drawn * width / intervals,
				   scale_rate(old_rate)));
		}
		if (line.rate > 0) {
		    line.elt.points.appendItem(
                        make_point(drawn * width / intervals,
				   scale_rate(line.rate)));
		}
	    }

	    if (count > 0) {
		drawn += count;
		lines.forEach(extend_line);
		elapsed -= count * grain;
		worked = 0;
	    }

            worked += work;
        }

	i = 1;
	time_end = Date.now();

	function draw_some() {
	    var now = Date.now();
	    time_end = now + Math.max(100, 0.5 * (now - time_end));

	    for (; i < rows.length; i++) {
		tick(rows[i].nTime - rows[i-1].nTime, rows[i].work);

		if (Date.now() >= time_end) {
		    break;
		}
	    }

	    matrix = svg.createSVGMatrix();

	    if (lo !== hi) {
		matrix.d = height / 1.1 / (lo - hi);
		matrix.f = height / 1.05 - lo * matrix.d;
		//matrix.f = 1 + lo / (hi - lo);
	    }

	    chart_transform =
		chart.transform.baseVal.createSVGTransformFromMatrix(matrix);

	    chart.transform.baseVal.initialize(chart_transform);

	    if (i < rows.length) {
		window.setTimeout(draw_some);
		return;
	    }

	    add_mouse();
	}

	function getEventPoint(event) {
            return [event.clientX, event.clientY];
	}

	var drag;

	function handle_mousedown(event) {
	    drag = getEventPoint(event);

	    // Prevent a containing HTML document from letting us drag
	    // the SVG "image".
	    event.preventDefault();
	}

	function handle_mousemove(event) {
	    var p, x, y, m;

	    if (drag) {
		p = getEventPoint(event);
		x = p[0] - drag[0], y = p[1] - drag[1];

		if (x !== 0 || y !== 0) {
	            m = event.target.getScreenCTM().inverse();
                    x *= m.a;
                    y *= m.d;

		    m = chart_transform.matrix;
                    //console.log(["move:", x, y, m.a, m.b, m.c, m.d, m.e, m.f]);
		    m.e += x;
		    m.f += y;
		    drag = p;
		}
		event.preventDefault();
	    }
	}

	function handle_mouseup(event) {
	    handle_mousemove(event);
	    drag = undefined;
	}

	function handle_wheel(event) {
	    var p = getEventPoint(event), x = p[0], y = p[1];
	    var d = Math.exp(-0.05 * event.deltaY);
	    var m;

	    m = event.target.getScreenCTM().inverse();
	    p = [m.a*x + m.c*y + m.e, m.b*x + m.d*y + m.f];
            x = p[0];
            y = p[1];

            m = chart_transform.matrix;
	    m.e -= x * m.a * (d - 1);
	    m.f -= y * m.d * (d - 1);
	    m.a *= d;
	    m.d *= d;

	    event.preventDefault();
	}

	function handle_nonstandard_mousewheel(event) {
	    event.deltaY = event.detail || -0.025 * event.wheelDelta;
	    handle_wheel(event);
	}

	function add_mouse() {
	    svg.addEventListener('mousedown', handle_mousedown, true);
	    svg.addEventListener('mouseup', handle_mouseup, true);
	    svg.addEventListener('mousemove', handle_mousemove, true);
	    //svg.addEventListener('wheel', handle_wheel, true);
	    svg.addEventListener('mousewheel', handle_nonstandard_mousewheel, true);
	    svg.addEventListener('DOMMouseScroll', handle_nonstandard_mousewheel, true);
	}

	draw_some();
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
