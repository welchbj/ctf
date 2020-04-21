#!/usr/bin/env python2
​
import struct
import sys
​
from collections import namedtuple
​
DirNode = namedtuple('DirNode', ['symbol', 'dirAddr', 'parentAddr'])
​
def getBytes(fs, pos, numBytes):
  fs.seek(pos)
  byte = fs.read(numBytes)
  if (numBytes == 2):
    formatString = "H"
  elif (numBytes == 1):
    formatString = "B"
  elif (numBytes == 4):
    formatString = "i"
  else:
    raise Exception("Not implemented")
  return struct.unpack("<"+formatString, byte)[0]
​
def getString(fs, pos, numBytes):
  fs.seek(pos)
  raw = fs.read(numBytes)
  return struct.unpack(str(numBytes)+"s", raw)[0]
​
def bytesPerSector(fs):
  return getBytes(fs,11,2)
​
def sectorsPerCluster(fs):
  return getBytes(fs,13,1)
​
def reservedSectorCount(fs):
  return getBytes(fs,14,2)
​
def numberOfFATs(fs):
  return getBytes(fs,16,1)
​
def FATStart(fs, numFat):
  return reservedSectorCount(fs) * bytesPerSector(fs)
​
def FATSize(fs):
  return getBytes(fs, 36, 4)
​
def rootStart(fs):
  return FATStart(fs,1) + (FATSize(fs) * numberOfFATs(fs) * bytesPerSector(fs))
​
def fsIdentityString(fs):
  return getString(fs,82,8)
​
def main(fs):
  offset = rootStart(fs)
​
  _dirEntryEnd = 0x127080
​
  _rootStart = rootStart(fs)
  _sectorsPerCluster = sectorsPerCluster(fs)
  _bytesPerSector = bytesPerSector(fs)
​
  matchOffsets = []
  dirNodes = []
  addrToDirNodeMap = {}
​
  def clusterToOffset(_clusterNum):
    return (
        _rootStart + (_clusterNum - 2) * _sectorsPerCluster * _bytesPerSector
    )
​
  def clusterStartAligned(_offset):
    while abs(_offset - 0x126a00) % 2048:
      _offset -= 1
    return _offset
​
  while offset <= _dirEntryEnd:
    fs.seek(offset + 0x0B)
    isLFN = (struct.unpack("b", fs.read(1))[0] == 0x0F)
​
    fs.seek(offset)
    fileName = struct.unpack("11s", fs.read(11))[0]
​
    fileName = fileName.strip()
    if fileName == "\x00\x00\x00\x00\x00\x00\x00\x00":
      continue
​
    # Read directory entry cluster number.
    fs.seek(offset + 26)
    clusterNum = struct.unpack("<H", fs.read(2))[0]
    dataOffset = clusterToOffset(clusterNum)
​
    dirAddr = dataOffset
    parentAddr = clusterStartAligned(offset)
    node = DirNode(fileName, dirAddr, parentAddr)
​
    if fileName == 'MATCH':
        matchOffsets.append(parentAddr)
​
    if dirAddr not in addrToDirNodeMap:
        addrToDirNodeMap[dirAddr] = []
    addrToDirNodeMap[dirAddr].append(node)
​
    fs.seek(offset)
    offset += 32
​
  for offset in matchOffsets:
      nodeList = addrToDirNodeMap.get(offset, None)
​
      if nodeList is not None:
          for node in nodeList:
              print followNode(addrToDirNodeMap, node, '')
​
def followNode(addrToDirNodeMap, startNode, flag):
    flag = startNode.symbol + flag
    print flag
​
    if flag.startswith('PCTF{'):
      return flag
​
    parentNodeList = addrToDirNodeMap.get(startNode.parentAddr, None)
    if parentNodeList is None:
      return None
​
    for parentNode in parentNodeList:
      maybe_flag = followNode(addrToDirNodeMap, parentNode, flag)
      if maybe_flag is not None:
        return maybe_flag
​
def ppNum(num):
  return "%s (%s)" % (hex(num), num)
​
if __name__ == "__main__":
    fs = open("strcmp.fat32","rb")
    print "Bytes per sector:",        ppNum(bytesPerSector(fs))
    print "Sectors per cluster:",     ppNum(sectorsPerCluster(fs))
    print "Reserved sector count:",   ppNum(reservedSectorCount(fs))
    print "Number of FATs:",          ppNum(numberOfFATs(fs))
    print "Start of FAT1:",           ppNum(FATStart(fs, 1))
    print "Start of root directory:", ppNum(rootStart(fs))
    print "Identity string:",         fsIdentityString(fs)
    main(fs)