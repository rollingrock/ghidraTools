import os
import re

symbolsIn = open("symbols.xml", 'r')

out = open("out.dd64", 'w')

out.writelines("{\n")
out.writelines(' "labels": [\n')

firstTime = True

for l in symbolsIn:
    match = re.search("ADDRESS=\"(.*)\" NAME=\"(\S*)\"", l)

    if match != None:
        name = match.group(2)[:1900]
        address = match.group(1).replace("0x14", "0x")

        if (firstTime):
            out.writelines('  {\n')
            firstTime = False
        else:
            out.writelines(',\n  {\n')

        out.writelines('   "text": "' + name + '",\n')
        out.writelines('   "manual": false,\n')
        out.writelines('   "module": "fallout4.exe",\n')
        out.writelines('   "address": "' + address + '"\n')
        out.writelines('  }')




out.writelines('\n ],\n')
out.writelines(' "breakpoints": []\n')
out.writelines("}\n")
        
