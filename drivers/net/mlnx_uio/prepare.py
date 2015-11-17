#!/usr/bin/env python3
import re
import os
import os.path
import sys

source_ext = ['.c','.cc','.cpp','.cxx']
header_ext = ['.h','.hpp','.hh','.hxx']

root_dir = sys.argv[1]

makefile_path = os.path.join(root_dir, "driver_sources.mk")

target_source = []

for curdir, subdirs, files in os.walk(os.path.join(root_dir, "mlnx")):
    for f in files:
        name,ext = os.path.splitext(f)
        if not (ext in source_ext):
            continue
        target_source.append((curdir, f))

with open (makefile_path, "w") as makefile:
    for (d,source) in target_source:
        relpath = os.path.relpath(os.path.join(d,source), root_dir)
        makefile.write("\tSRCS-$(CONFIG_RTE_LIBRTE_MLNX_UIO_PMD) += " + relpath + "\n")

 
