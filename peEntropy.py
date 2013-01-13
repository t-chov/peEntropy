# -*- coding: utf-8 -*-

#�����������ׂ�t�@�C���̖��O�ł�

import sys
import math
import struct

#���ς̎擾
def GetAverage(array):
	total = 0.0
	for value in array:
		total += value
	average = total / len(array)
	return average

#�G���g���s�[�x�[�X�̃p�b�L���O���m�N���X
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
	#�G���g���s�[���v�Z����Z�N�V�����̌���
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
	#n�o�C�g�ڂ���m�o�C�g�ڂ܂ł�x�o�C�g���Ƃ̕��σG���g���s�[���o��
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
