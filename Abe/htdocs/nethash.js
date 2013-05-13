// Copyright(C) 2013 by John Tobey <jtobey@john-edwin-tobey.org>
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

    function draw(svg, interval) {
        var ctx, i, elts, node, windows, chart, lines, rows, work, first;
        var elapsed, worked, drawn, width, height, intervals, matrix;
        var difficulty_rate;

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

        function make_point(x, value) {
            var y = this.scale_rate(value), point = this.svg.createSVGPoint();
            point.x = x
            point.y = y;
            if (y < this.lo) this.lo = y;
            if (y > this.hi) this.hi = y;
            return point;
        }

        function parse_window(s) {
            var m, n;

            m = /^(\d*(?:\.\d+)?)(d|days?)$/i.exec(s);

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

        function scale_rate(rate) {
            return Math.log(rate);
        }

        function make_line(elt) {
            var line = { elt: elt }, window;

            window = elt.getAttributeNS(ABE_NS, "window");

            if (window == null) {
                line.block_time = Number(
                    elt.getAttributeNS(ABE_NS, "block-time"));

                if (line.block_time <= 0) {
                    throw "Invalid block_time for difficulty line: " +
                        line.block_time;
                }

                difficulty_rate = rows[0].difficulty / line.block_time;
                line.rate = difficulty_rate;
            }
            else {
                line.oldShare = 1 / Math.exp(interval / parse_window(window));
                line.newShare = 1 - line.oldShare;
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

        ctx = {
            svg: svg,
            lines: lines,
            rows: rows,
            make_point: make_point,
            hi: -Infinity,
            lo: Infinity,

            // XXX Should use the chart element's dimensions, not <svg>.
            width: svg.viewBox.baseVal.width,
            height: svg.viewBox.baseVal.height,
            elapsed: 0,
            worked: 0,
            drawn: 0
        };

        function init_line(line) {
            line.rate = first;
            line.elt.points.initialize(make_point(0, line.rate));
        }
        lines.forEach(init_line);

        rows.sort(function(a, b) { return a.nTime - b.nTime; });
        ctx.intervals = Math.ceil((rows[rows.length-1].nTime - rows[0].nTime) /
                                  interval);

        drawSome(ctx);
    }

    function drawSome(ctx) {
        var t = this;
        var i, elts, node, windows, chart, lines, rows, work, first;
        var elapsed, worked, drawn, width, height, intervals, matrix;
        var difficulty_rate;



        function extend_line(line) {
            if (line.block_time) {
                line.rate = rows[i].difficulty / line.block_time;
            }
            else {
                line.rate *= line.oldShare;
                line.rate += line.newShare * worked / interval;
            }
            if (line.rate > 0) {
                line.elt.points.appendItem(make_point(drawn * width / intervals,
                                                      line.rate));
            }
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

        if (lo !== hi) {
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
