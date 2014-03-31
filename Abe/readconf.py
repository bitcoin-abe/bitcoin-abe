# Copyright(C) 2011,2012,2013 by Abe developers.

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

def looks_like_json(val):
    return val[:1] in ('"', '[', '{') or val in ('true', 'false', 'null')

def parse_argv(argv, conf={}, config_name='config', strict=False):
    arg_dict = conf.copy()
    args = lambda var: arg_dict[var]
    args.func_dict = arg_dict

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg == '--':
            i += 1
            break
        if arg[:2] != '--':
            break

        # Strip leading "--" to form a config variable.
        # --var=val and --var val are the same.  --var+=val is different.
        split = arg[2:].split('=', 1)
        adding = False
        if len(split) == 1:
            var = split[0]
            if i + 1 < len(argv) and argv[i + 1][:2] != '--':
                i += 1
                val = argv[i]
            else:
                val = True
        else:
            var, val = split
            if var[-1:] == '+':
                var = var[:-1]
                adding = True

        if val is not True and looks_like_json(val):
            val = parse_json(val)

        var = var.replace('-', '_')
        if var == config_name:
            _include(set(), val, arg_dict, config_name, strict)
        elif var not in conf:
            break
        elif adding:
            add(arg_dict, var, val)
        else:
            arg_dict[var] = val
        i += 1

    return args, argv[i:]

def include(filename, conf={}, config_name='config', strict=False):
    _include(set(), filename, conf, config_name, strict)
    return conf

class _Reader:
    __slots__ = ['fp', 'lineno', 'line']
    def __init__(rdr, fp):
        rdr.fp = fp
        rdr.lineno = 1
        rdr.line = rdr.fp.read(1)
    def eof(rdr):
        return rdr.line == ''
    def getc(rdr):
        if rdr.eof():
            return ''
        ret = rdr.line[-1]
        if ret == '\n':
            rdr.lineno += 1
            rdr.line = ''
        c = rdr.fp.read(1)
        if c == '':
            rdr.line = ''
        rdr.line += c
        return ret
    def peek(rdr):
        if rdr.eof():
            return ''
        return rdr.line[-1]
    def _readline(rdr):
        ret = rdr.fp.readline()
        rdr.line += ret
        return ret
    def readline(rdr):
        ret = rdr.peek() + rdr._readline()
        rdr.getc()  # Consume the newline if not at EOF.
        return ret
    def get_error_context(rdr, e):
        e.lineno = rdr.lineno
        if not rdr.eof():
            e.offset = len(rdr.line)
            if rdr.peek() != '\n':
                rdr._readline()
            e.text = rdr.line

def _include(seen, filename, conf, config_name, strict):
    if filename in seen:
        raise Exception('Config file recursion')

    with open(filename) as fp:
        rdr = _Reader(fp)
        try:
            entries = read(rdr)
        except SyntaxError, e:
            if e.filename is None:
                e.filename = filename
            if e.lineno is None:
                rdr.get_error_context(e)
            raise
    for var, val, additive in entries:
        var = var.replace('-', '_')
        if var == config_name:
            import os
            _include(seen | set(filename),
                     os.path.join(os.path.dirname(filename), val), conf,
                     config_name, strict)
        elif var not in conf:
            if strict:
                raise ValueError(
                    "Unknown parameter `%s' in %s" % (var, filename))
        elif additive and conf[var] is not None:
            add(conf, var, val)
        else:
            conf[var] = val
    return

def read(rdr):
    """
    Read name-value pairs from file and return the results as a list
    of triples: (name, value, additive) where "additive" is true if
    "+=" occurred between name and value.

    "NAME=VALUE" and "NAME VALUE" are equivalent.  Whitespace around
    names and values is ignored, as are lines starting with '#' and
    empty lines.  Values may be JSON strings, arrays, or objects.  A
    value that does not start with '"' or '{' or '[' and is not a
    boolean is read as a one-line string.  A line with just "NAME"
    stores True as the value.
    """
    entries = []
    def store(name, value, additive):
        entries.append((name, value, additive))

    def skipspace(rdr):
        while rdr.peek() in (' ', '\t', '\r'):
            rdr.getc()

    while True:
        skipspace(rdr)
        if rdr.eof():
            break
        if rdr.peek() == '\n':
            rdr.getc()
            continue
        if rdr.peek() == '#':
            rdr.readline()
            continue

        name = ''
        while rdr.peek() not in (' ', '\t', '\r', '\n', '=', '+', ''):
            name += rdr.getc()

        if rdr.peek() not in ('=', '+'):
            skipspace(rdr)

        if rdr.peek() in ('\n', ''):
            store(name, True, False)
            continue

        additive = False

        if rdr.peek() in ('=', '+'):
            if rdr.peek() == '+':
                rdr.getc()
                if rdr.peek() != '=':
                    raise SyntaxError("'+' without '='")
                additive = True
            rdr.getc()
            skipspace(rdr)

        if rdr.peek() in ('"', '[', '{'):
            js = scan_json(rdr)
            try:
                store(name, parse_json(js), additive)
            except ValueError, e:
                raise wrap_json_error(rdr, js, e)
            continue

        # Unquoted, one-line string.
        value = ''
        while rdr.peek() not in ('\n', ''):
            value += rdr.getc()
        value = value.strip()

        # Booleans and null.
        if value == 'true':
            value = True
        elif value == 'false':
            value = False
        elif value == 'null':
            value = None

        store(name, value, additive)

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

def _scan_json_string(rdr):
    ret = rdr.getc()  # '"'
    while True:
        c = rdr.getc()
        if c == '':
            raise SyntaxError('End of file in JSON string')

        # Accept raw control characters for readability.
        if c == '\n':
            c = '\\n'
        if c == '\r':
            c = '\\r'
        if c == '\t':
            c = '\\t'

        ret += c
        if c == '"':
            return ret
        if c == '\\':
            ret += rdr.getc()

def _scan_json_nonstring(rdr):
    # Assume we are at a number or true|false|null.
    # Scan the token.
    ret = ''
    while rdr.peek() != '' and rdr.peek() in '-+0123456789.eEtrufalsn':
        ret += rdr.getc()
    return ret

def _scan_json_space(rdr):
    # Scan whitespace including "," and ":".  Strip comments for good measure.
    ret = ''
    while not rdr.eof() and rdr.peek() in ' \t\r\n,:#':
        c = rdr.getc()
        if c == '#':
            c = rdr.readline() and '\n'
        ret += c
    return ret

def _scan_json_compound(rdr):
    # Scan a JSON array or object.
    ret = rdr.getc()
    if ret == '{': end = '}'
    if ret == '[': end = ']'
    ret += _scan_json_space(rdr)
    if rdr.peek() == end:
        return ret + rdr.getc()
    while True:
        if rdr.eof():
            raise SyntaxError('End of file in JSON value')
        ret += scan_json(rdr)
        ret += _scan_json_space(rdr)
        if rdr.peek() == end:
            return ret + rdr.getc()

def scan_json(rdr):
    # Scan a JSON value.
    c = rdr.peek()
    if c == '"':
        return _scan_json_string(rdr)
    if c in ('[', '{'):
        return _scan_json_compound(rdr)
    ret = _scan_json_nonstring(rdr)
    if ret == '':
        raise SyntaxError('Invalid JSON')
    return ret

def parse_json(js):
    import json
    return json.loads(js)

def wrap_json_error(rdr, js, e):
    import re
    match = re.search(r'(.*): line (\d+) column (\d+)', e.message, re.DOTALL)
    if match:
        e = SyntaxError(match.group(1))
        json_lineno = int(match.group(2))
        e.lineno = rdr.lineno - js.count('\n') + json_lineno - 1
        e.text = js.split('\n')[json_lineno - 1]
        e.offset = int(match.group(3))
        if json_lineno == 1 and json_line1_column_bug():
            e.offset += 1
    return e

def json_line1_column_bug():
    ret = False
    try:
        parse_json("{:")
    except ValueError, e:
        if "column 1" in e.message:
            ret = True
    finally:
        return ret
