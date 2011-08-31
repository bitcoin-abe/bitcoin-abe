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
        add = False
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
                add = True

        if val is not True and val[:1] in ('"', '[', '{'):
            val = parse_json(val, var)

        var = var.replace('-', '_')
        if var == config_name:
            include(val, arg_dict, strict=strict)
        elif var not in conf:
            break
        elif add:
            add(arg_dict, var, val)
        else:
            arg_dict[var] = val
        i += 1

    return args, argv[i:]

def include(filename, conf={}, config_name='config', strict=False):
    _include(set(), filename, conf, config_name, strict)
    return conf

def _include(seen, filename, conf, config_name, strict):
    if filename in seen:
        raise Exception('Config file recursion')

    with open(filename) as fp:
        entries = read(fp)
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
            store(name, parse_json(js, name), additive)
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
    # Scan whitespace including "," and ":".  Strip comments for good measure.
    ret = ''
    while c != '' and c in ' \t\r\n,:#':
        if c == '#':
            while c not in ('', '\n'):
                c = fp.read(1)
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

def parse_json(js, context):
    try:
        import json
        return json.loads(js)
    except Exception, e:
        raise SyntaxError('Invalid JSON for %s: %s' % (context, e))
