#!/usr/bin/env python

__description__ = 'Network Appliance Forensic Toolkit - IOS Core Dumps'
__author__ = 'Didier Stevens'
__version__ = '0.0.5'
__date__ = '2013/03/30'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/12/05: start
  2011/12/06: continue
  2011/12/12: continue
  2012/01/25: refactoring for cIOSCoreDump
  2012/01/26: IOSCWStrings
  2012/01/27: Added command processes
  2012/01/29: Added option minimum
  2012/01/30: Continue processes
  2012/01/31: Continue processes
  2012/02/01: refactoring
  2012/02/13: V0.0.3: dProcessStructureStats
  2012/02/15: heuristics
  2012/02/20: V0.0.5: added IOSHistory
  2012/02/22: added IOSEvents, refactoring
  2013/03/30: added IOSCheckText
  2013/03/31: continued IOSCheckText

Todo:
"""

import optparse
import struct
import re
import naft_uf
import naft_impf
import naft_pfef
import naft_iipf

def IOSRegions(coredumpFilename, options):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
    else:
        print('Start      End        Size       Name')
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                print('0x%08X 0x%08X %10d %s' % (region[1], region[1] + region[2] - 1, region[2], region[0]))
                if options.write:
                    naft_uf.Data2File(oIOSCoreDump.Region(region[0])[1], '%s-%s-0x%08X' % (coredumpFilename, region[0], region[1]))
            else:
                print('0x%08X %s %s' % (region[1], ' ' * 21, region[0]))
        addressBSS, dataBSS = oIOSCoreDump.RegionBSS()

def IOSHeap(coredumpFilename, options):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParser = naft_impf.cIOSMemoryParser(memoryHeap)
    if options.resolve or options.filter != '':
        oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    if options.filter == '':
        oIOSMemoryParser.Show()
    else:
        print(naft_impf.cIOSMemoryBlockHeader.ShowHeader)
        for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
            if oIOSMemoryBlockHeader.AllocNameResolved == options.filter:
                if not options.strings:
                    print(oIOSMemoryBlockHeader.ShowLine())
                if options.strings:
                    dStrings = naft_uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
                    if options.grep != '':
                        printHeader = True
                        for key, value in dStrings.items():
                            if value.find(options.grep) >= 0:
                                if printHeader:
                                    print(oIOSMemoryBlockHeader.ShowLine())
                                    printHeader = False
                                print(' %08X: %s' % (oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value))
                    elif options.minimum == 0 or len(dStrings) >= options.minimum:
                        print(oIOSMemoryBlockHeader.ShowLine())
                        for key, value in dStrings.items():
                            print(' %08X: %s' % (oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.BlockSize + key, value))
                if options.dump:
                    naft_uf.DumpBytes(oIOSMemoryBlockHeader.GetData(), oIOSMemoryBlockHeader.address + oIOSMemoryBlockHeader.headerSize)

def IOSFrames(coredumpFilename, filenameIOMEM, filenamePCAP, options):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
        return
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return
    oIOSMemoryParserHeap = naft_impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParserHeap.ResolveNames(oIOSCoreDump)
    dataIOMEM = naft_uf.File2Data(filenameIOMEM)
    oIOSMemoryParserIOMEM = naft_impf.cIOSMemoryParser(dataIOMEM)
    addressIOMEM = oIOSMemoryParserIOMEM.baseAddress
    if addressIOMEM == None:
        print('Error parsing IOMEM')
        return
    oFrames = naft_pfef.cFrames()
    print(naft_impf.cIOSMemoryBlockHeader.ShowHeader)
    for oIOSMemoryBlockHeader in oIOSMemoryParserHeap.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == '*Packet Header*':
            frameAddress = struct.unpack('>I', oIOSMemoryBlockHeader.GetData()[40:44])[0]
            frameSize = struct.unpack('>H', oIOSMemoryBlockHeader.GetData()[72:74])[0]
            if frameAddress != 0 and frameSize != 0:
                print(oIOSMemoryBlockHeader.ShowLine())
                naft_uf.DumpBytes(dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], frameAddress)
                oFrames.AddFrame(frameAddress - addressIOMEM, dataIOMEM[frameAddress - addressIOMEM : frameAddress - addressIOMEM + frameSize], True)
    oFrames.WritePCAP(filenamePCAP)

def IOSCWStringsSub(data):
    oCWStrings = naft_impf.cCiscoCWStrings(data)
    if oCWStrings.error != '':
        print(oCWStrings.error)
        return
    keys = oCWStrings.dCWStrings.keys()
    keys.sort()
    for key in keys:
        if key == 'CW_SYSDESCR':
            print('%s:' % key)
            print(oCWStrings.dCWStrings[key])
        else:
            print('%s:%s%s' % (key, ' ' * (22 - len(key)), oCWStrings.dCWStrings[key]))

def IOSCWStrings(coredumpFilename, options):
    if options.raw:
        coredump = naft_uf.File2Data(coredumpFilename)
        if coredump == None:
            print('Error reading file %s' % coredumpFilename)
        else:
            IOSCWStringsSub(coredump)
    else:
        oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
        if oIOSCoreDump.error  != '':
            print(oIOSCoreDump.error)
            return
        addressData, memoryData = oIOSCoreDump.RegionDATA()
        if memoryData == None:
            print('Data region not found')
            return
        IOSCWStringsSub(memoryData)

def PrintStatsAnalysis(dStats, oIOSCoreDump):
    keys1 = dStats.keys()
    keys1.sort()
    for key1 in keys1:
        countKeys = len(dStats[key1])
        keys2 = dStats[key1].keys()
        keys2.sort()
        if countKeys > 2 and countKeys <= 7:
            bucket = '-> ' + ' '.join(['%X:%d' % (key2, dStats[key1][key2]) for key2 in keys2])
        else:
            bucket = ''
        filtered = filter(lambda x: x != 0, dStats[key1])
        if filtered == []:
            filteredMin = min(dStats[key1])
        else:
            filteredMin = min(filtered)
        unfilteredMax = max(dStats[key1])
        regionNames = []
        for region in oIOSCoreDump.regions:
            if region[2] != None:
                if filteredMin >= region[1] and filteredMin <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
                if unfilteredMax >= region[1] and unfilteredMax <= region[1] + region[2] - 1:
                    if not region[0] in regionNames:
                        regionNames.append(region[0])
        regionNames.sort()
        regionName = ' '.join(regionNames).strip()
        print('%3d %3X: %3d %08X %08X %08X %s %s' % (key1, key1*4, countKeys, min(dStats[key1]), filteredMin, unfilteredMax, regionName, bucket))

def IOSProcesses(coredumpFilename, options):
    oIOSCoreDumpAnalysis = naft_impf.cIOSCoreDumpAnalysis(coredumpFilename)
    if oIOSCoreDumpAnalysis.error != '':
        print(oIOSCoreDumpAnalysis.error)
        return

    for (processID, addressProcess, oIOSProcess) in oIOSCoreDumpAnalysis.processes:
        if options.filter == '' or processID == int(options.filter):
            if oIOSProcess != None:
                if oIOSProcess.error == '':
                    line = oIOSProcess.Line()
                else:
                    line = '%4d %s' % (processID, oIOSProcess.error)
                print(line)
                if options.dump:
                    naft_uf.DumpBytes(oIOSProcess.data, addressProcess)
            else:
                print('addressProcess not found %d %08X' % (processID, addressProcess))

    if oIOSCoreDumpAnalysis.RanHeuristics:
        print('')
        print('*** WARNING ***')
        print('Unexpected process structure')
        print('Please reports these results')
        print('Fields determined with heuristics:')
        print('Process structure size: %d' % oIOSCoreDumpAnalysis.HeuristicsSize)
        keys = oIOSCoreDumpAnalysis.HeuristicsFields.keys()
        keys.sort(key=str.lower)
        for key in keys:
            value = oIOSCoreDumpAnalysis.HeuristicsFields[key]
            if value != None:
                print('%-22s: 0x%04X' % (key, value[1]))

    if options.statistics:
        keys = oIOSCoreDumpAnalysis.dProcessStructureStats.keys()
        keys.sort()
        print('Number of different process structures: %d' % len(keys))
        for index in keys:
            print('Process structures length: %d' % index)
            PrintStatsAnalysis(oIOSCoreDumpAnalysis.dProcessStructureStats[index], oIOSCoreDumpAnalysis.oIOSCoreDump)

def FilterInitBlocksForString(coredumpFilename, searchTerm):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
        return []
    addressHeap, memoryHeap = oIOSCoreDump.RegionHEAP()
    if memoryHeap == None:
        print('Heap region not found')
        return []
    oIOSMemoryParser = naft_impf.cIOSMemoryParser(memoryHeap)
    oIOSMemoryParser.ResolveNames(oIOSCoreDump)
    found = []
    for oIOSMemoryBlockHeader in oIOSMemoryParser.Headers:
        if oIOSMemoryBlockHeader.AllocNameResolved == 'Init':
            dStrings = naft_uf.SearchASCIIStrings(oIOSMemoryBlockHeader.GetData())
            for value in dStrings.values():
                if value.find(searchTerm) >= 0:
                    found.append(value)
    return found

def IOSHistory(coredumpFilename, options=None):
    history = []
    for command in FilterInitBlocksForString(coredumpFilename, 'CMD: '):
        oMatch = re.search("'(.+)' (.+)", command)
        if oMatch:
            history.append((oMatch.group(2), oMatch.group(1)))
    for command in sorted(history, key=lambda x: x[0]):
        print('%s: %s' % command)

def IOSEvents(coredumpFilename, options=None):
    for event in sorted(FilterInitBlocksForString(coredumpFilename, ': %')):
        print(event)

def IOSCheckText(coredumpFilename, imageFilename, options):
    oIOSCoreDump = naft_impf.cIOSCoreDump(coredumpFilename)
    if oIOSCoreDump.error  != '':
        print(oIOSCoreDump.error)
        return
    else:
        textAddress, textCoredump = oIOSCoreDump.RegionTEXT()
        if textCoredump == None:
            print('Error extracting text region from coredump %s' % coredumpFilename)
            return
        sysdescrCoredump = ''
        dataAddress, dataCoredump = oIOSCoreDump.RegionDATA()
        if dataCoredump != None:
            oCWStrings = naft_impf.cCiscoCWStrings(dataCoredump)
            if oCWStrings.error == '' and 'CW_SYSDESCR' in oCWStrings.dCWStrings:
                sysdescrCoredump = oCWStrings.dCWStrings['CW_SYSDESCR']

    image = naft_uf.File2Data(imageFilename)
    if image == None:
        print('Error reading image %s' % imageFilename)
        return

    oIOSImage = naft_iipf.cIOSImage(image)
    if oIOSImage.error != 0:
        return
    sysdescrImage = ''
    if oIOSImage.oCWStrings != None and oIOSImage.oCWStrings.error == '' and 'CW_SYSDESCR' in oIOSImage.oCWStrings.dCWStrings:
        sysdescrImage = oIOSImage.oCWStrings.dCWStrings['CW_SYSDESCR']
    if sysdescrCoredump != '' or sysdescrImage != '':
        if sysdescrCoredump == sysdescrImage:
            print('CW_SYSDESCR are identical:\n')
            print(sysdescrCoredump)
        elif sysdescrCoredump == sysdescrImage.replace('-MZ', '-M', 1):
            print('CW_SYSDESCR are equivalent:\n')
            print(sysdescrCoredump)
        else:
            print('CW_SYSDESCR are different:\n')
            print(sysdescrCoredump)
            print
            print(sysdescrImage)
        print

    oELF = naft_iipf.cELF(oIOSImage.imageUncompressed)
    if oELF.error != 0:
        print('ELF parsing error %d.' % oELF.error)
        return
    countSectionExecutableInstructions = 0
    for oSectionHeader in oELF.sections:
        if oSectionHeader.flags & 4: # SHF_EXECINSTR executable instructions
            textSectionData = oSectionHeader.sectionData
            countSectionExecutableInstructions += 1
    if countSectionExecutableInstructions != 1:
        print('Error executable sections in image: found %d sections, expected 1' % countSectionExecutableInstructions)
        return
    start = textAddress & 0xFF # to be further researched
    textImage = textSectionData[start:start + len(textCoredump)]
    if len(textCoredump) != len(textImage):
        print('the text region is longer than the text section')
    countBytesDifferent = 0
    shortestLength = min(len(textCoredump), len(textImage))
    for iIter in range(shortestLength):
        if textCoredump[iIter] != textImage[iIter]:
            if countBytesDifferent == 0:
                print('text region and section are different starting 0x%08X in coredump (iter = 0x%08X)' % ((textAddress + iIter), iIter))
            countBytesDifferent += 1
    if countBytesDifferent == 0:
        print('text region and section are identical')
    else:
        print('number of different bytes: %d (%.2f%%)' % (countBytesDifferent, (countBytesDifferent * 100.0) / shortestLength))

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] command arguments ...\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--dump', action='store_true', default=False, help='dump data')
    oParser.add_option('-s', '--strings', action='store_true', default=False, help='dump strings in data')
    oParser.add_option('-m', '--minimum', type=int, default=0, help='minimum count number of strings')
    oParser.add_option('-g', '--grep', default='', help='grep strings')
    oParser.add_option('-r', '--resolve', action='store_true', default=False, help='resolve names')
    oParser.add_option('-f', '--filter', default='', help='filter for given name')
    oParser.add_option('-a', '--raw', action='store_true', default=False, help='search in the whole file for CW_ strings')
    oParser.add_option('-w', '--write', action='store_true', default=False, help='write the regions to disk')
    oParser.add_option('-t', '--statistics', action='store_true', default=False, help='Print process structure statistics')
    (options, args) = oParser.parse_args()

    dCommands = {
                    'regions':   (2, IOSRegions,   'coredump: identify regions in core dump, options w'),
                    'cwstrings': (2, IOSCWStrings, 'coredump: extract CW_ strings, options a'),
                    'heap':      (2, IOSHeap,      'coredump: list heap linked list, options rfdsgm'),
                    'history':   (2, IOSHistory,   'coredump: list command history'),
                    'events':    (2, IOSEvents,    'coredump: list events'),
                    'frames':    (4, IOSFrames,    'coredump iomem pcap-file: extract frames and store them in pcap-file'),
                    'processes': (2, IOSProcesses, 'coredump: list processes, options fdt'),
                    'checktext': (3, IOSCheckText, 'coredump image: compare the text section in memory and image'),
                }

    if len(args) == 0:
        oParser.print_help()
        print('')
        print('Commands:')
        for command, config in dCommands.items():
            print('  %s %s' % (command, config[2]))
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return
    elif not args[0] in dCommands:
        print('unknown command')
        return

    if len(args) == dCommands[args[0]][0]:
        dCommands[args[0]][1](*(args[1:] + [options]))
    else:
        print('Error: expected %d arguments, you provided %d arguments' % (dCommands[args[0]][0], len(args)))

if __name__ == '__main__':
    Main()
