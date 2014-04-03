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
