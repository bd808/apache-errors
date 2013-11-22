#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013 Bryan Davis and contributors

"""
Apache error log report generator
"""

import collections
import datetime
import hashlib
import re
import string
import textwrap

ERROR_FORMAT = (
        r'\[(?P<datetime>[^\]]+)\] '
        r'\[(?P<level>[^\]]+)\] '
        r'(\[client (?P<ip>[^\]]+)\] )?'
        r'(?P<message>.*)'
    )
RE_ERROR_FORMAT = re.compile(ERROR_FORMAT)

IGNORE_ITEM = '~~bd808.ignore.item~~'


def parse_error_log (lines, logpat=RE_ERROR_FORMAT):
    """
    Parse a log file into a sequence of dictionaries

    Args:
        lines: line generator
        logpat: regex to split lines

    Returns:
        generator of mapped lines
    """
    groups = (logpat.match(line) for line in lines)

    tuples = (g.groupdict() for g in groups if g)
    log = field_map(tuples, 'message', expand_newlines)
    log = field_map(log, 'datetime', format_date)
    return log
#end parse_error_log


def field_map (dictseq, name, func):
    """
    Process a sequence of dictionaries and remap one of the fields

    Typically used in a generator chain to coerce the datatype of a particular
    field. eg ``log = field_map(log, 'status', int)``

    Args:
        dictseq: Sequence of dictionaries
        name: Field to modify
        func: Modification to apply
    """
    for d in dictseq:
        if name in d:
            d[name] = func(d[name])
        yield d
#end field_map


def format_date (d):
    """
    Convert apache dates formatted as "Thu Mar 03 16:13:22 2011" to standard iso
    date format.

    Args:
        d: date string to reformat

    Returns:
        ISO 8601 formatted date (YYYY-MM-DDTHH:MM:SS)
    """
    return datetime.datetime.strptime(d, '%a %b %d %H:%M:%S %Y').isoformat()
#end format_date


def expand_newlines (src):
    """
    Replace occurances of the chars "\n" with an actual newline.

    Args:
        src: input string

    Returns:
        expanded string
    """
    return string.replace(src, r'\n', '\n')
#end expand_newlines


def reduce_pattern_matches (x, y):
    """
    Combine pattern map output by combining groupdict() results into a single
    dict. If either argument is None then the result is None because all
    patterns must match for the expectation to match.

    Args:
        x: re.MatchObject, dict or None
        y: re.MatchObject or None
    Return:
        dict with all matched catptures or None
    """
    if x is None or y is None:
        return None
    captures = x if isinstance(x, dict) else x.groupdict()
    captures.update(y.groupdict())
    return captures
#end reduce_pattern_matches


def print_report (log, expect):
    """
    Print a report to stdout based on the given log generator and expected
    message configuration.

    If the regex for a given label includes named pattern captures those named
    captures can be used alter the label for a particular match. For example:
    >>> e = { 'found %(val)s': re.compile(r'something (?P<val>\d+)'), }

    The special label defined in the IGNORE_ITEM constant can be used to
    silently discard lines that are not desired to be reported as an occurance
    count or an unexpected entry.

    The generated report will have a block of label: count pairs at the top
    followed by pretty printed versions of any log entries that were found but
    not expected.

    Args:
        log: log generator
        expect: list of (label, dict) patterns
    """
    found = collections.defaultdict(int)
    extra = []
    dup = collections.defaultdict(int)
    output = False
    processed = collections.defaultdict(int)

    for r in log:
        unexpected = True
        processed[r['level']] += 1

        for exp in expect:
            try:
                m = reduce(reduce_pattern_matches,
                                map(lambda p: p[1].match(r[p[0]]), exp['match'].items()))
            except KeyError:
                m = None

            if m is not None:
                # grab named matches from pattern match
                replace_keys = m if isinstance(m, dict) else m.groupdict()

                # merge in raw log data so keys can use it
                replace_keys.update(r)

                # increment counter named by applying found tokens to format
                try:
                    found[exp['format'] % replace_keys] += 1

                except (KeyError, ValueError):
                    #print "DEBUG: failed to expand template '%s' with %s" % (
                    #        exp['format'], replace_keys)
                    found[exp['format']] += 1

                output = True # found something to report
                unexpected = False
                break;
        #end for

        if unexpected and r['level'] not in ['debug', 'notice']:
            # ignore debug and notice messages, too noisy
            key = hashlib.sha1(r['message']).hexdigest()
            if key not in dup:
                extra.append((r, key))
            dup[key] += 1
    #end for

    print "%-50s : %7s" % ("error", "count")
    print "=" * 60
    prior_prefix = None

    def colonFirst (x, y):
        xe = x.split()[0][-1]
        ye = y.split()[0][-1]
        if xe == ye:
            return cmp(x, y)
        elif xe == ':':
            return -1
        elif ye == ':':
            return 1
        else:
            return cmp(x, y)

    for item in sorted(found.keys(), cmp=colonFirst):
        if item == IGNORE_ITEM:
            processed['IGNORED'] = found[item]
            continue

        prefix = item.split()[0]
        if prior_prefix is not None:
            if ((prior_prefix[-1] == ':' and prefix <> prior_prefix)
                 or (prefix[-1] == ':' and prefix <> prior_prefix)
                 or (prior_prefix[-1] == ':' and prefix[-1] <> ':')
                ):
                print

        print "%-50s : %7d" % (item, found[item])
        prior_prefix = prefix
    print

    # sort remaining messages by date
    def date_sort (a, b):
        return cmp(a[0]['datetime'], b[0]['datetime']);

    extra.sort(date_sort)

    if (len(extra) > 0):
        output = True # found something to report
        print "Unclassified messages"
        print "=" * 60

        wrapit = textwrap.TextWrapper(subsequent_indent='    ')
        for t in extra:
            (r, key) = t
            dups = dup[key]
            fmt = ""
            fargs = []
            if dups > 1:
                fmt += "<{}> "
                fargs.append(dups)
            fmt += "[{}] [{}] {}"
            fargs.extend([r['datetime'], r['level'], r['message']])

            maxlines = 10
            for line in fmt.format(*fargs).split("\n"):
                maxlines = maxlines - 1
                if maxlines < 0:
                    print " ...truncated..."
                    break

                if len(line) > wrapit.width:
                    print "\n  ".join(wrapit.wrap(line))
                else:
                    print " ", line
            print

    if not output:
        print "no data to report"
    # end if

    print "\n\n--- processed",
    for key in sorted(processed.keys()):
        print "%s=%d" % (key, processed[key]),
    print
#end print_report


def compile_expects (elist):
    """
    Compile a list of expectations.

    Expectations are dictionaries. The key 'format' is expected to exist in the
    dict and provide a format string for summarizing the log entry. The key
    'match' provides a dict of log record field names and regex patterns to
    match on those fields.

    Args:
        expect: list of expectation dicts
    Returns:
        list of expectation dicts with values replaced by compiled regexs
    """
    ret = []
    for rec in elist:
        # compile regular expressions
        for key, value in rec['match'].iteritems():
            rec['match'][key] = re.compile(value.replace('\\\\', '\\'), re.DOTALL)
        ret.append(rec)

    return ret
#end compile_expects


if __name__ == '__main__':
    """simple command line tool to extract named fields from a log on stdin."""

    import optparse
    import os
    import sys

    parser = optparse.OptionParser(usage="usage: %prog [options] < example.log")

    parser.add_option("-y", "--yaml",
        help="YAML file of expected messages. Multiple uses allowed",
        action='append',
        metavar="FILE")


    (options, args) = parser.parse_args()

    expect = []
    if options.yaml:
        import yaml

        expect = []
        for abs_path in options.yaml:
            f = open(abs_path, 'r')
            expect += yaml.load(f)
            f.close()
        #end for
        expect = compile_expects(expect)

    print_report(parse_error_log(sys.stdin), expect)

# vim:sw=4 ts=4 sts=4 et:
