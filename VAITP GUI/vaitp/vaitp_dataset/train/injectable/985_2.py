#!/usr/bin/python3 -O

# freewvs - a free web vulnerability scanner
#
# https://freewvs.schokokeks.org/
#
# Written by schokokeks.org Hosting, https://schokokeks.org
#
# Contributions by
# Hanno Boeck, https://hboeck.de/
# Fabian Fingerle, https://fabian-fingerle.de/
# Bernd Wurst, https://bwurst.org/
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software. If not, see
# https://creativecommons.org/publicdomain/zero/1.0/
# Nevertheless, in case you use a significant part of this code, we ask (but
# not require, see the license) that you keep the authors' names in place and
# return your changes to the public. We would be especially happy if you tell
# us what you're going to do with this code.

import os
import glob
import re
import argparse
import sys
import json
import pathlib
from xml.sax.saxutils import escape  # noqa: DUO107


def versioncompare(safe_version, find_version):
    if safe_version == "":
        return True
    try:
      safe_version_tup = [int(x) for x in safe_version.split(".")]
      find_version_tup = [int(x) for x in find_version.split(".")]
      return find_version_tup < safe_version_tup
    except ValueError:
      return False

def vulnprint(appname, version, safeversion, vuln, vfilename, subdir,
              xml):
    appdir = '/'.join(os.path.abspath(vfilename).split('/')[:-1 - subdir])
    if not xml:
        print("%(appname)s %(version)s (%(safeversion)s) %(vuln)s "
              "%(appdir)s" % vars())
    else:
        state = 'vulnerable'
        if safeversion == 'ok':
            state = 'ok'
        print('  <app state="%s">' % state)
        print('    <appname>%s</appname>' % escape(appname))
        print('    <version>%s</version>' % escape(version))
        print('    <directory>%s</directory>' % escape(appdir))
        if state == 'vulnerable':
            print('    <safeversion>%s</safeversion>' % escape(safeversion))
            print('    <vulninfo>%s</vulninfo>' % escape(vuln))
        print('  </app>')


# Command-line options
parser = argparse.ArgumentParser()
parser.add_argument("dirs", nargs="*",
                    help="Directories to scan")
parser.add_argument("-a", "--all", action="store_true",
                    help="Show all webapps found, not just vulnerable")
parser.add_argument("-x", "--xml", action="store_true",
                    help="Output results as XML")
parser.add_argument("-3", "--thirdparty", action="store_true",
                    help="Scan for third-party components like jquery")
opts = parser.parse_args()

# Warn people with old-style freewvsdb dirs,
# should be removed in a few months
for d in ["/usr/share/freewvs", "/usr/local/share/freewvs"]:
    if os.path.isdir(d):
        print("WARNING: Obsolete freewvs data in %s, removal recommended" % d,
              file=sys.stderr)

jdir = False
for p in [os.path.dirname(sys.argv[0]) + '/freewvsdb', '/var/lib/freewvs',
          str(pathlib.Path.home()) + "/.cache/freewvs/"]:
    if os.path.isdir(p):
        jdir = p
        break
if not jdir:
    print("Can't find freewvs json db")
    sys.exit(1)

jconfig = []
for cfile in glob.glob(os.path.join(jdir, '*.json')):
    try:
        with open(cfile, 'r') as json_file:
            data = json.load(json_file)
            jconfig.extend(data)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading json file {cfile}: {e}", file=sys.stderr)


scanfiles = set()
for app in jconfig:
    for det in app['detection']:
        scanfiles.add(det['file'])


if opts.xml:
    print('<?xml version="1.0" ?>')
    print('<freewvs>')

# start the search

for fdir in opts.dirs:
    for root, dirs, files in os.walk(fdir):
        # this protects us against nested directories causing
        # an exception
        if root.count(os.sep) > 500:
            del dirs[:]
        for filename in scanfiles.intersection(files):
            for item in jconfig:
                if not opts.thirdparty and 'thirdparty' in item:
                    continue
                for det in item['detection']:
                    if filename == det['file']:
                        mfile = os.path.join(root, filename)
                        try:
                            with open(mfile, 'r', errors='replace') as file:
                                filestr = file.read()
                        except IOError:
                            continue

                        if (('extra_match' in det
                             and det['extra_match'] not in filestr)
                                or ('extra_nomatch' in det
                                    and det['extra_nomatch'] in filestr)):
                            continue

                        if ('path_match' in det
                                and (not root.endswith(det['path_match']))):
                            continue
                        try:
                            findversion_match = re.search(re.escape(det['variable'])
                                                    + r"[^0-9\n\r]*[.]*"
                                                    "([0-9.]*[0-9])[^0-9.]",
                                                    filestr)
                            if not findversion_match:
                                continue
                            findversion = findversion_match.group(1)
                        except re.error:
                            continue


                        # Very ugly phpbb workaround
                        if 'add_minor' in det:
                            try:
                                findversion = findversion.split('.')
                                findversion[-1] = str(int(findversion[-1])
                                                    + int(det['add_minor']))
                                findversion = '.'.join(findversion)
                            except (ValueError, IndexError):
                                continue

                        if ((not versioncompare(item['safe'], findversion))
                                or ('old_safe' in item
                                    and findversion in
                                    item['old_safe'].split(','))):
                            if opts.all:
                                vulnprint(item['name'], findversion, "ok", "",
                                          mfile, det['subdir'], opts.xml)
                            continue

                        safev = item['safe']
                        if 'old_safe' in item:
                            for ver in item['old_safe'].split(','):
                                if versioncompare(ver, findversion):
                                    safev = ver

                        vulnprint(item['name'], findversion, safev,
                                  item['vuln'], mfile, det['subdir'], opts.xml)

if opts.xml:
    print('</freewvs>')
    