# Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/gpl.html>.

def read(fp):
    """
    Read name-value pairs from fp and return the result as a
    dictionary.

    Multiple values having the same name become lists.  "NAME=VALUE"
    and "NAME VALUE" are equivalent.  Whitespace around names and
    values is ignored, as are lines starting with '#' and empty lines.
    Values may be JSON strings, arrays, or objects.  A value that does
    not start with '"' or '{' or '[' is read as a one-line string.  A
    line with just "NAME" stores True as the value.
    """
    conf = {}
    def store(name, value):
        if name in conf:
            o = conf[name]
            if isinstance(o, list):
                o.append(value)
            else:
                conf[name] = [o, value]
        else:
            conf[name] = value

    c = fp.read(1)
    while True:
        if c == '':
            break
        while c in (' ', '\t'):
            c = fp.read(1)
        if c == '\n':
            c = fp.read(1)
            continue
        if c == '#':
            fp.readline()
            c = fp.read(1)
            continue
        name = ''
        while c not in (' ', '\t', '\n', '=', ''):
            name += c
            c = fp.read(1)
        if c in ('\n', ''):
            store(name, True)
            continue
        seen_eq = (c == '=')
        c = fp.read(1)
        while c in (' ', '\t', '='):
            if c == '=':
                if seen_eq:
                    break
                seen_eq = True
            c = fp.read(1)

        if c in ('"', '[', '{'):
            # Scan to end of JSON object.  Grrr, why can't json.py do this
            # without reading all of fp?
            def scan_string(fp):
                ret = '"'
                while True:
                    c = fp.read(1)
                    if c == '':
                        raise ValueError('End of file in JSON string')
                    ret += c
                    if c == '"':
                        return ret, fp.read(1)
                    if c != '\\':
                        continue
                    c = fp.read(1)
                    ret += c
                    if c == 'u':
                        ret += fp.read(4)

            def scan_nonstring(fp, c):
                ret = ''
                while c != '' and c in '-+0123456789.eEtrufalsn':
                    ret += c
                    c = fp.read(1)
                return ret, c

            def scan_space(fp, c):
                ret = ''
                while True:
                    if c == '' or c not in ' \t\n,:':
                        return ret, c
                    ret += c
                    c = fp.read(1)

            def scan_compound(fp, c, end):
                ret = c
                cs, c = scan_space(fp, fp.read(1))
                ret += cs
                if c == end:
                    return ret + c, fp.read(1)
                while True:
                    if c == '':
                        raise ValueError('End of file in JSON value')
                    cs, c = scan_value(fp, c)
                    ret += cs
                    cs, c = scan_space(fp, c)
                    ret += cs
                    if c == end:
                        return ret + c, fp.read(1)

            def scan_value(fp, c):
                if c == '"':
                    return scan_string(fp)
                if c == '[':
                    return scan_compound(fp, c, ']')
                if c == '{':
                    return scan_compound(fp, c, '}')
                cs, c = scan_nonstring(fp, c)
                if cs == '':
                    raise ValueError('Invalid initial JSON character: ' + c)
                return cs, c

            js, c = scan_value(fp, c)
            import json
            store(name, json.loads(js))
            continue

        value = ''
        while c not in ('\n', ''):
            value += c
            c = fp.read(1)
        store(name, value.rstrip())

    return conf
