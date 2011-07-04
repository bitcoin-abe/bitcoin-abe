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

def include(filename, conf):
    _include(set(), filename, conf)

def _include(seen, filename, conf):
    if filename in seen:
        raise Exception('Config file recursion')

    with open(filename) as fp:
        entries = read(fp)
    for var, val, add in entries:
        var = var.replace('-', '_')
        if var == 'config':
            _include(seen + [filename],
                     os.path.join(os.path.dirname(filename), val), conf)
        elif add:
            add(conf, var, val)
        else:
            conf[var] = val
    return

def read(fp):
    """
    Read name-value pairs from fp and return the results as a list of
    triples: (name, value, additive) where "additive" is true if "+="
    occurred between name and value.

    "NAME=VALUE" and "NAME VALUE" are equivalent.  Whitespace around
    names and values is ignored, as are lines starting with '#' and
    empty lines.  Values may be JSON strings, arrays, or objects.  A
    value that does not start with '"' or '{' or '[' is read as a
    one-line string.  A line with just "NAME" stores True as the
    value.
    """
    entries = []
    def store(name, value, additive):
        entries.append((name, value, additive))

    def skipspace(c):
        while c in (' ', '\t', '\r'):
            c = fp.read(1)
        return c

    c = fp.read(1)
    while True:
        c = skipspace(c)
        if c == '':
            break
        if c == '\n':
            c = fp.read(1)
            continue
        if c == '#':
            fp.readline()
            c = fp.read(1)
            continue

        name = ''
        while c not in (' ', '\t', '\r', '\n', '=', '+', ''):
            name += c
            c = fp.read(1)

        if c not in ('=', '+'):
            c = skipspace(c)

        if c in ('\n', ''):
            store(name, True, False)
            continue

        additive = False

        if c in ('=', '+'):
            if c == '+':
                c = fp.read(1)
                if c != '=':
                    raise SyntaxError("Unquoted '+'")
                additive = True
            c = skipspace(fp.read(1))

        if c in ('"', '[', '{'):
            js, c = scan_json(fp, c)
            import json
            store(name, json.loads(js), additive)
            continue

        # Unquoted, one-line string.
        value = ''
        while c not in ('\n', ''):
            value += c
            c = fp.read(1)
        store(name, value.rstrip(), additive)

    return entries

def add(conf, var, val):
    if var not in conf:
        conf[var] = val
        return

    if isinstance(val, dict) and isinstance(conf[var], dict):
        conf[var].update(val)
        return

    if not isinstance(conf[var], list):
        conf[var] = [conf[var]]
    if isinstance(val, list):
        conf[var] += val
    else:
        conf[var].append(val)

# Scan to end of JSON object.  Grrr, why can't json.py do this without
# reading all of fp?

def _scan_json_string(fp):
    ret = '"'
    while True:
        c = fp.read(1)
        if c == '':
            raise SyntaxError('End of file in JSON string')
        ret += c
        if c == '"':
            return ret, fp.read(1)
        if c == '\\':
            c = fp.read(1)
            ret += c

def _scan_json_nonstring(fp, c):
    # Assume we are at a number or true|false|null.
    # Scan the token.
    ret = ''
    while c != '' and c in '-+0123456789.eEtrufalsn':
        ret += c
        c = fp.read(1)
    return ret, c

def _scan_json_space(fp, c):
    # Scan whitespace including "," and ":".
    ret = ''
    while c != '' and c in ' \t\r\n,:':
        ret += c
        c = fp.read(1)
    return ret, c

def _scan_json_compound(fp, c, end):
    # Scan a JSON array or object.
    ret = c
    cs, c = _scan_json_space(fp, fp.read(1))
    ret += cs
    if c == end:
        return ret + c, fp.read(1)
    while True:
        if c == '':
            raise SyntaxError('End of file in JSON value')
        cs, c = scan_json(fp, c)
        ret += cs
        cs, c = _scan_json_space(fp, c)
        ret += cs
        if c == end:
            return ret + c, fp.read(1)

def scan_json(fp, c):
    # Scan a JSON value.
    if c == '"':
        return _scan_json_string(fp)
    if c == '[':
        return _scan_json_compound(fp, c, ']')
    if c == '{':
        return _scan_json_compound(fp, c, '}')
    cs, c = _scan_json_nonstring(fp, c)
    if cs == '':
        raise SyntaxError('Invalid initial JSON character: ' + c)
    return cs, c
