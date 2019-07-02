import os
import re

dirstats = {}
lvls = 3
namepattern = re.compile(r'^[A-F0-9]{32}.bin$')
replacepattern = re.compile(r'[A-F0-9]{2}')
for name in os.listdir('dump'):
    name = 'dump/' + name
    if not os.path.isfile(name) or not namepattern.match(os.path.basename(name)):
        continue
    newname = replacepattern.sub('\g<0>/', name, lvls)
    dirname = os.path.dirname(newname)
    if dirname not in dirstats:
        dirstats[dirname] = 0
    dirstats[dirname] += 1
    os.makedirs(dirname, exist_ok=True)
    os.rename(name, newname)

print("Maximum number of files in folder:", max(dirstats.values()))
