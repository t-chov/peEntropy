# -*- coding: utf-8 -*-

#第一引数が調べるファイルの名前です

import sys
import math
import struct

#平均の取得
def GetAverage(array):
	total = 0.0
	for value in array:
		total += value
	average = total / len(array)
	return average

#エントロピーベースのパッキング検知クラス
class DetectPacking:
	def __init__(self, fpath):
		self.binaries = open(fpath, 'rb').read()
		self.length = len(self.binaries)
		self.offsetToPE00 = struct.unpack('L', self.binaries[60:64])[0]
		self.baseOfCode = struct.unpack('L',
				self.binaries[(self.offsetToPE00 + 44):(self.offsetToPE00 + 48)])[0]
		self.numOfSections = struct.unpack('H',
				self.binaries[(self.offsetToPE00+6):(self.offsetToPE00+8)])[0]
		self.entropy = 0.0
		self.SearchTargetSection()
	#エントロピーを計算するセクションの検索
	def SearchTargetSection(self):
		for sectionNumber in range(0, self.numOfSections):
			startPosition = self.offsetToPE00 + 248 + 40 * sectionNumber
			virtualAddress = struct.unpack('L',
					self.binaries[(startPosition + 12):(startPosition + 16)])[0]
			if self.baseOfCode == virtualAddress:
				entryPoint = struct.unpack('L',
					self.binaries[(startPosition + 20):(startPosition + 24)])[0]
				sectionSize = struct.unpack('L',
					self.binaries[(startPosition + 16):(startPosition + 20)])[0]
				self.entropy = self.CalcEntropy(entryPoint,
																				entryPoint+sectionSize, 512)
				break
	#nバイト目からmバイト目までのxバイトごとの平均エントロピーを出す
	def CalcEntropy(self, start, end, margin):
		count = [0] * 256
		entropies = []
		for point in range(start, end):
			count[ord(self.binaries[point])] += 1
			if point != start and (point - start) % margin == 0:
				ent = 0.0
				for num in count:
					if num != 0:
						prob = float(num) / margin
						ent += -1 * prob * math.log(prob, 2)
				entropies.append(ent)
				count = [0] * 256
		return GetAverage(entropies)

param = sys.argv
try:
	pe = DetectPacking(param[1])
except:
	print "File Error"
	exit()

print "File name: " + str(param[1])
print "Entropy in entry section: " + str(pe.entropy)
if pe.entropy > 6.85:
	print "It is maybe packed."
else:
	print "It is maybe native PE file."
