#!/usr/bin/env python3

'''
EScript decompiler for binary ECL files version 2 (POL092)
'''

import os, sys
import logging
import string


def parseInt(val):
	''' Parses an int in binary format. First byte is the least significant
	
	The most significant bit of the most significant byte represents the sign (+ if 0, - if 1)
	'''
	if len(val) < 1:
		raise ValueError("Can't parse an empty string")
	ret = 0
	pos = 0
	for char in val:
		i = int(char)
		if pos + 1 == len(val):
			# This is the most significant bit, check for the sign
			if i & 0b10000000:
				mul = -1
				i &= 0b10000000
			else:
				mul = 1
		ret += i * 0x100 ** pos
		pos += 1
	return ret * mul

def parseFloat(val):
	''' Parses a float in binary format '''
	if len(val) != 8:
		raise ValueError("Floats must be 8 bytes long")
	#FIXME: This is absolutely wrong!!
	mant = parseInt(val[:6])
	exp = parseInt(val[6:])
	return str(mant) + '/' + str(exp)

def parseStr(val, fixed=False):
	''' Parses a string in binary format. NULL terminated
	
	@param fixed boolean: If given, makes sure that all the bytes after the NULL terminator are null too
	'''
	ret = ''
	term = False
	for char in val:
		if term and char != 0:
			raise ValueError("Unexpected non-null byte {:02X} after null terminator".format(char))

		if char != 0:
			ret += chr(char)
		elif fixed:
			term = True
		else:
			break
	return ret


class ECLFile:

	def __init__(self, inFile):
		self.log = logging.getLogger('eclfile')
		# Buffer where file data will be stored
		self.buf = b''
		# Pointer position counter
		self.pos = 0

		# Will contain the parsed "use" blocks
		self.usages = []
		# Will contain the parsed instructions block
		self.instr = None
		# Will contain the parses constants block
		self.const = None
		# Will contain the program block definition
		self.program = None

		with open(inFile, 'rb') as f:
			while True:
				data = f.read(4096)
				if data == b'':
					break
				self.buf += data

		self.log.info('Loaded %d bytes from %s', len(self.buf), inFile)

		# Reads the header
		try:
			self.parseHeader(self.buf[self.pos:6])
		except ParseError as e:
			self.log.critical(e)
			sys.exit(1)
		self.pos = 6

		# Reads blocks
		while True:
			try:
				block = self.getNextBlock()
			except ParseError as e:
				self.log.critical(e)
				sys.exit(1)

			if isinstance(block, UsageBlock):
				self.usages.append(block)
			elif isinstance(block, InstructionsBlock):
				if self.instr is not None:
					self.log.critical('Duplicate instructions block found')
					sys.exit(1)
				self.instr = block
			elif isinstance(block, ConstantsBlock):
				if self.const is not None:
					self.log.critical('Duplicate constants block found')
					sys.exit(1)
				self.const = block
			elif isinstance(block, ProgramBlock):
				if self.program is not None:
					self.log.critical('Duplicate program block found')
					sys.exit(1)
				self.program = block
			else:
				self.log.critical('Unsupported block %s', block)
				sys.exit(1)

			self.pos += 6 + block.size()
			if self.pos == len(self.buf):
				# EOF
				break

	def parseHeader(self, header):
		''' Parses the 6 bytes header field '''
		if header[:2] != b'CE':
			raise ParseError('This is not a valid eScript file, wrong magic number')
		if header[2] != 2:
			raise ParseError('This is not a POL093 eScript file, wrong version number {}'.format(header[2]))
		if header[3] != 0:
			raise ParseError('unexpected non-zero byte 4 in header: {}'.format(header[3]))
		self.log.warning('Unknown byte 5 in header is set to {:02X}'.format(header[4]))
		if header[5] != 0:
			raise ParseError('unexpected non-zero byte 6 in header: {}'.format(header[5]))

	def getNextBlock(self):
		''' Scans the buffer and returns next block '''
		self.log.info('Looking for a block at pos 0x%X', self.pos)

		blockHeader = self.buf[self.pos : self.pos+6]
		self.log.debug('Block header %s', blockHeader)
		code = parseInt(blockHeader[:2])
		size = parseInt(blockHeader[2:])
		self.log.info('Found block code %d, declared size %d', code, size)

		if size == 0 and code == 1:
			# Block code 1 doesn't specify a size, go read it from block's data
			size = 13 + int(self.buf[self.pos+6+9]) * 34
			self.log.info('Deduced size of %d bytes for the block', size)
		elif code == 1 and size != 0:
			raise ParseError('Unsupported block code 1 with a given size')
		elif size == 0:
			raise ParseError('Unsupported zero-sized block')

		data = self.buf[self.pos+6 : self.pos+6+size]
		if len(data) != size:
			raise RuntimeError('Data len mismatch')
		self.log.debug('Raw block data: %s', data)

		if code == 1:
			return UsageBlock(data)
		elif code == 2:
			return InstructionsBlock(data)
		elif code == 3:
			return ConstantsBlock(data)
		elif code == 4:
			return ProgramBlock(data)
		else:
			raise ParseError('Unsupported block code %d', code)

	def dump(self):
		''' Dump useful informations '''
		print('*** USAGES ***')
		i = 0
		for u in self.usages:
			print('0x{:02X} {}'.format(i, u))
			i += 1
		print()

		if self.program:
			print('*** PROGRAM ***')
			print('{} arguments'.format(self.program.args))
			print()

		print('*** {} INSTRUCTIONS ***'.format(len(self.instr)))
		for idx, ir in enumerate(self.instr.instr):
			print('0x{:02X}'.format(idx) + ' - ' + ir.descr(self.const, self.usages))
		print()

		print('*** CONSTANTS ***')
		print(self.const)
		print()


class Block:
	''' Base class for a generic block '''

	def __init__(self, code, data):
		''' Constructor
		@param code int: The block code
		@param data binary: The RAW block data
		'''
		self.log = logging.getLogger('block')
		self.code = code
		self.data = data

	def size(self):
		''' Returns block length (excluding header) '''
		return len(self.data)


class UsageBlock(Block):
	''' A block type 01: "use" directive '''

	def __init__(self, data):
		super().__init__(1, data)
		self.name = parseStr(data[:9], True)
		funcCount = int(data[9])
		if data[10:12] != b'\x00\x00':
			raise ParseError('Unexpected data in bytes 11-13 of block: %s', data[10:12])
		self.func = []
		for i in range(0,funcCount):
			f = data[13+i*34 : 13+i*34+34]
			self.func.append(UsageBlockFunction(f))
		self.log.debug('New usage block %s, functions: %s', self.name, self.func)

	def __str__(self):
		return self.name + ' [' + ', '.join([str(i) for i in self.func]) + ']'

class UsageBlockFunction():
	''' A function inside and usage block '''

	def __init__(self, data):
		self.name = parseStr(data[:33], True)
		self.parm = int(data[33])

	def __repr__(self):
		return self.name + '(' + str(self.parm) + 'p)'


class InstructionsBlock(Block):
	''' A block type 02: instructions '''

	def __init__(self, data):
		super().__init__(2, data)
		innerSize = parseInt(data[:4])
		if innerSize != len(data) - 4:
			raise ParseError('Unexpected block inner size')

		inner = data[4:]
		if len(inner) % 5:
			raise ParseError('Instructions data size is not a multiple of 5')

		self.instr = [Instruction(inner[i:i+5]) for i in range(0, len(inner), 5)]

	def __len__(self):
		return len(self.instr)

class Instruction():
	''' A single instruction '''

	def __init__(self, data):
		self.log = logging.getLogger('instr')
		if len(data) != 5:
			raise ParseError('An instruction must be 5 bytes long')
		self.data = data
		# Try to identify instruction type, I am pretty sure this can be done
		# way better than this way...
		if data[1] == 0x2f:
			self.type = 'run'
		elif data[0] == 0x01:
			self.type = 'load'
		elif data[0] == 0x02:
			self.type = 'assign'
		elif data[0] == 0x03:
			self.type = 'clear'
		elif data[0] == 0x08 and data[1] in (0x2a,0x2b):
			self.type = 'var'
		elif data[0] == 0x08 and data[1] in (0x25,0x26):
			self.type = 'gotoif'
		elif data[0] == 0x0f:
			self.type = 'return'
		else:
			self.type = 'unknown'

	def descr(self, const, usages):
		''' Returns instruction's description
		@param const: The constants block in use
		@param usages: The usages list in use
		'''
		base = repr(self)

		try:

			if self.type == 'run':
				if self.data[2:4] != b'\x00\x00':
					raise ParseError('Unexpected run instr {}'.format(self))
				uid = int(self.data[4])
				fid = int(self.data[0])
				us = usages[uid]
				desc = us.name + ':' + str(us.func[fid])

			elif self.type == 'load':
				pos = parseInt(self.data[2:])
				typ = int(self.data[1])
				if typ >= 0x32:
					typ = typ - 0x32

				if typ == 0:
					typ = 'int'
					val = const.getInt(pos)
				elif typ == 1:
					typ = 'float'
					val = const.getFloat(pos)
				elif typ == 2:
					typ = 'str'
					val = const.getStr(pos)
				else:
					self.log.critical(repr(self))
					raise ParseError('Unknown type {}'.format(typ))

				if int(self.data[1]) >= 0x32:
					desc = 'var ' + typ + ' #' + str(pos)
				else:
					desc = 'const ' + typ + ' <' + str(val) + '>'

			elif self.type == 'assign':
				opt = self.data[1]
				if opt == 0x42 or opt == 0x08:
					if self.data[2:] != b'\x00\x00\x00':
						raise ParseError('Unexpected assign instr {}'.format(self))
					desc = 'W1 := W2'
					if opt == 0x08:
						desc += ' oneline'
				elif opt == 0x38:
					desc = 'program parm ' + const.getStr(parseInt(self.data[2:]))
				else:
					raise ParseError('Unexpected assign instr {}'.format(self))

			elif self.type == 'clear':
				if self.data[1:] != b'\x19\x00\x00\x00':
					raise ParseError('Unexpected clear instr {}'.format(self))
				desc = ''

			elif self.type == 'var':
				scope = self.data[1]
				if scope == 0x2b:
					scope = 'global'
				elif scope == 0x2a:
					scope = 'program'
				else:
					raise ParseError('Var instr with unkown scope {}'.format(self))
				vid = parseInt(self.data[2:])
				desc = scope + ' #' + str(vid)

			elif self.type == 'gotoif':
				cond = self.data[1]
				if cond == 0x25:
					cond = 'true'
				elif cond == 0x26:
					cond = 'false'
				else:
					raise ParseError('GotoIf instr with unkown cond {}'.format(self))
				pos = parseInt(self.data[2:])
				desc = 'if W1 == {} goto 0x{:02X}'.format(cond, pos)

			elif self.type == 'return':
				if self.data[1:] != b'\x20\x00\x00\x00':
					raise ParseError('Unexpected return instr {}'.format(self))
				desc = ''

			else:
				desc = ''

		except ParseError as e:
			desc = str(e)
		except Exception as e:
			print('ERROR: {}'.format(self))
			raise e
		
		if desc:
			return base + ': ' + desc
		else:
			return base

	def __repr__(self):
		hx = ' '.join(['{:02X}'.format(c) for c in self.data])
		#hb = ' '.join(['{:08b}'.format(c) for c in self.data[:2]])
		return hx + ' - ' + '{:>6s}'.format(self.type)


class ConstantsBlock(Block):
	''' A block type 03: constants '''

	def __init__(self, data):
		super().__init__(3, data)
		innerSize = parseInt(data[:4])
		if innerSize != len(data) - 4:
			raise ParseError('Unexpected block inner size')

	def getInt(self, pos):
		''' Returns integer at given position '''
		return parseInt(self.data[pos+4 : pos+4+4])

	def getFloat(self, pos):
		''' Returns a float at given position '''
		return parseFloat(self.data[pos+4 : pos+4+8])

	def getStr(self, pos):
		''' Returns string at given position '''
		return parseStr(self.data[pos+4:])

	def __repr__(self):
		inner = self.data[4:]
		hx = ['{:02X}'.format(c) for c in inner]
		ex = len(hx) % 16
		if ex:
			hx.extend(['  '] * ex)

		ret = ''
		row = ''
		i = 1
		for x in hx:
			ret += x
			if x != '  ':
				char = chr(inner[i-1])
			else:
				char = ' '
			if char not in string.printable:
				char = '.'
			row += char
			if not i % 16:
				ret += '  ' + row + '\n'
				row = ''
			elif not i % 4:
				ret += '  '
				row += ' '
			else:
				ret += ' '
			i += 1
		return ret


class ProgramBlock(Block):
	''' A block type 04: program '''

	def __init__(self, data):
		super().__init__(4, data)
		self.args = int(self.data[0])
		if data[1:] != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
			raise ParseError('Unexpected data in bytes 2-16 of block: %s', data[1:])


class ParseError(RuntimeError):
	pass


if __name__ == '__main__':
	import argparse

	logging.basicConfig(level=logging.INFO)

	parser = argparse.ArgumentParser()
	parser.add_argument('ecl_file', help='The compiled script')
	args = parser.parse_args()
	ecl = ECLFile(args.ecl_file)
	ecl.dump()
