#!/usr/bin/env python3
import re
import os
import os.path
import sys

source_ext = ['.c','.cc','.cpp','.cxx']
header_ext = ['.h','.hpp','.hh','.hxx']

root_dir = sys.argv[1]

for curdir, subdirs, files in os.walk(root_dir):
#    if( not ("source_list" in files)):
#        continue
    for source in files:
        purename, extension = os.path.splitext(source)
        if (not extension in source_ext) and (not extension in header_ext):
            continue

        with open (os.path.join(curdir, source), 'r') as source_file:
            source_string= source_file.readlines() #map(lambda s: s.rstrip('\n'), source_file.readlines())
        if '#define K_CONVERTED\n' in source_string:
            continue

        source_string.insert(0, '#include \"kmod.h\"\n')
        #if '#include <linux/skbuff.h>\n' in source_string:
        #   source_string.insert(0, '#define K_SKBUFF\n')
        source_string.insert(0, '#endif\n')
        source_string.insert(0, '#define K_CONVERTED\n')
        source_string.insert(0, '#ifndef K_CONVERTED\n')
        out_lines = []

        with open (os.path.join(curdir, source), 'w') as source_file:
            rx_bracketed_include = re.compile(r'^.*(#include\s<[^>]+>).*$')
            for line in source_string:
                if not rx_bracketed_include.search(line):
                    out_lines.append(line)

#           rx_quoted_include = re.compile(r'^.*(#include\s*"[^"]+")$')
#           last_idx = 0
#           for idx, line in enumerate(out_lines):
#               if rx_quoted_include.search(line):
#                   last_idx = idx


            for line in out_lines:
                source_file.write(line)

            if extension in header_ext:
                source_file.write('\n#include "post_kmod.h"\n')
