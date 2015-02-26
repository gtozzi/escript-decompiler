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
		''' return useful informations as a dump
		@return list of lines
		'''
		yield('*** USAGES ***')
		i = 0
		for u in self.usages:
			yield('0x{:02X} {}'.format(i, u))
			i += 1
		yield('')

		if self.program:
			yield('*** PROGRAM ***')
			yield('{} arguments'.format(self.program.args))
			yield('')

		yield('*** {} INSTRUCTIONS ***'.format(len(self.instr)))
		for idx, ir in enumerate(self.instr.instr):
			yield('0x{:04X}'.format(idx) + ' - ' + ir.descr(self.const, self.usages))
		yield('')

		yield('*** CONSTANTS ***')
		yield(str(self.const))
		yield('')

	def source(self):
		''' Try to build back the source code for the script
		@return list of lines
		'''
		yield('// Source decompiled from binary using decompile.py')
		yield('// written by Scripter Bodom @ ZHI Time Warp shard <bodom@discosucks.it>')
		yield('// with the precious help of Scripter Evolution, from the same shard')
		yield('')

		# Registers and status variables
		blk = [] # Last block is the current block, also used as indentation level
		idx = 0 # Index of next instruction to be read
		var = [] # Map of var IDs => names
		reg = [] # Map of W registers

		# Utility functions
		def ind(row, mod=0):
			''' adds indentation to a row '''
			return '\t' * (len(blk)+mod) + row
		def quote(string):
			''' quotes a string '''
			#TODO: fixme
			return '"{}"'.format(string)
		def unquote(string):
			''' removes quotes from a quoted string '''
			#TODO: fixme
			return string[1:-1]

		# Start with usages
		for u in self.usages:
			if u.name not in ('basic','basicio'):
				yield('use {};'.format(u.name))
		yield('')

		# Start program block, if specified
		if self.program:
			parms = []
			# Expect fist instructions to define program variable names
			for i in range(idx,idx+self.program.args):
				inst = self.instr[i]
				desc, info = inst.parse(self.const, self.usages)
				if inst.type != 'assign' or info['type'] != 'program':
					self.log.critical('Assign program instruction expected')
				parms.append(info['parm'])
				var.append(info['parm'])
			yield('program decompiled(' + ', '.join(parms) + ')')

			blk.append({'type': 'program'})
			idx += self.program.args

		# Instructions being used by multiple instructions
		def clear(reg):
			if reg:
				yield(ind('{};'.format(reg[0])))
				reg.clear()

		# Parse the instructions
		while idx < len(self.instr):
			inst = self.instr[idx]
			desc, info = inst.parse(self.const, self.usages)

			# End if block if needed
			if blk and blk[-1]['type'] == 'if' and blk[-1]['end'] == idx:
				del blk[-1]
				yield(ind('endif'))

			# Parse next instruction
			if inst.type == 'run':
				parms = reg[0-info['func'].parm:]
				if len(parms) == 1 and parms[0] == '""':
					parms = [] # Omit a single null string parameter
				call = '{}({})'.format(info['func'].name, ', '.join(parms))
				reg.append(call)

			elif inst.type == 'method':
				reg.append('{}.{}({})'.format(reg[0], info['name'], reg[-1]))

			elif inst.type == 'load':
				if info['var']:
					reg.append(var[info['id']])
				elif info['type'] == 'str':
					reg.append(quote(info['val']))
				elif info['type'] in ('int','float'):
					reg.append('{}'.format(info['val']))
				else:
					self.log.error('unimplemented load')

			elif inst.type == 'assign':
				if info['type'] == 'left':
					reg[0] = '{} := {}'.format(reg[0], reg[-1])
				elif info['type'] == 'prop':
					reg[0] = '{}.{}'.format(reg[-2], unquote(reg[-1]))
				else:
					self.log.error('unimplemented assign')

			elif inst.type == 'clear':
				yield from clear(reg)

			elif inst.type == 'var':
				yield from clear(reg)
				var.append('v' + str(len(var)+1))
				reg.append(var[-1])
				yield(ind('var {};'.format(var[-1])))

			elif inst.type == 'goto':
				if info['cond'] is not None:
					# Conditional jump starts an if block
					op = ''
					if not info['cond']:
						op = '! '
					yield(ind('if( {}{} )'.format(op, reg[0])))
					# Expect to find an unconditional jump at to-1. This jump leads
					# to the end of the "if block"
					goto = self.instr[info['to']-1]
					el = None
					end = info['to']
					if goto.type == 'goto':
						# Also found an else statement
						el = info['to'] - 1
						gd, gi = goto.parse(self.const, self.usages)
						end = gi['to']
					blk.append({'type': 'if', 'else': el, 'end': end})
				elif info['cond'] is None and blk and blk[-1]['type'] == 'if' and blk[-1]['else'] == idx:
					# This is the else jump of the current "if" statement
					yield(ind('else',-1))
				else:
					self.log.error('unimplemented goto')

			elif inst.type == 'return':
				yield from clear(reg)
				if info['mode'] == 'program':
					if blk and blk[-1]['type'] == 'program':
						del blk[-1]
						yield(ind('endprogram'))
					else:
						self.log.critical('endprogram outside program block')
				elif info['mode'] == 'generic' and idx == len(self.instr)-1:
					pass # Ignore final return of the file
				else:
					self.log.error('unimplemented return')

			else:
				self.log.error('unimplemented instruction {}'.format(inst))

			self.log.debug("%s %s W:%s", inst.type, desc, reg)

			idx += 1


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

	def __getitem__(self, key):
		return self.instr[key]

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
		elif data[0] == 0x01 and data[1] == 0x03b:
			self.type = 'method'
		elif data[0] == 0x01:
			self.type = 'load'
		elif data[0] == 0x02:
			self.type = 'assign'
		elif data[0] == 0x03:
			self.type = 'clear'
		elif data[0] == 0x08 and data[1] in (0x2a,0x2b):
			self.type = 'var'
		elif data[0] == 0x08 and data[1] in (0x25,0x26,0x27):
			self.type = 'goto'
		elif data[0] == 0x0f:
			self.type = 'return'
		else:
			self.type = 'unknown'

	def parse(self, const, usages):
		''' Parses this instruction
		@param const: The constants block in use
		@param usages: The usages list in use
		@throws ParseError
		@return list: (readable description, info dictionary (instruction dependant))
		'''
		info = {}

		if self.type == 'run':
			if self.data[2:4] != b'\x00\x00':
				raise ParseError('Unexpected run instr {}'.format(self))
			uid = int(self.data[4])
			fid = int(self.data[0])
			us = usages[uid]
			fu = us.func[fid]
			info['usage'] = us
			info['func'] = fu
			desc = us.name + ':' + str(fu)

		elif self.type == 'method':
			pos = parseInt(self.data[2:])
			name = const.getStr(pos)
			info['name'] = name
			desc = 'W1.' + name

		elif self.type == 'load':
			pos = parseInt(self.data[2:])
			typ = int(self.data[1])

			if typ == 0x00:
				var = False
				typ = 'int'
				val = const.getInt(pos)
			elif typ == 0x01:
				var = False
				typ = 'float'
				val = const.getFloat(pos)
			elif typ == 0x02:
				var = False
				typ = 'str'
				val = const.getStr(pos)
			elif typ == 0x33:
				var = True
				typ = None
			else:
				self.log.critical(repr(self))
				raise ParseError('Unknown type {}'.format(typ))

			info['var'] = var
			if var:
				desc = 'var #' + str(pos)
				info['id'] = pos
			else:
				desc = 'const ' + typ + ' <' + str(val) + '>'
				info['val'] = val
				info['type'] = typ

		elif self.type == 'assign':
			opt = self.data[1]
			if opt == 0x42 or opt == 0x08:
				if self.data[2:] != b'\x00\x00\x00':
					raise ParseError('Unexpected assign instr {}'.format(self))
				desc = 'W1 := W<last>'
				info['type'] = 'left'
				if opt == 0x08:
					desc += ' oneline'
					info['oneline'] = True
				else:
					info['oneline'] = False
			elif opt == 0x1E:
				if self.data[2:] != b'\x00\x00\x00':
					raise ParseError('Unexpected assign instr {}'.format(self))
				desc = 'W1 := W<last-1>.W<last>'
				info['type'] = 'prop'
			elif opt == 0x38:
				parm = const.getStr(parseInt(self.data[2:]))
				desc = 'program parm ' + parm
				info['type'] = 'program'
				info['parm'] = parm
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
				scope = 'local'
			else:
				raise ParseError('Var instr with unkown scope {}'.format(self))
			info['scope'] = scope
			vid = parseInt(self.data[2:])
			info['id'] = vid
			desc = scope + ' #' + str(vid)

		elif self.type == 'goto':
			cond = self.data[1]
			if cond == 0x25:
				cond = True
			elif cond == 0x26:
				cond = False
			elif cond == 0x27:
				cond = None
			else:
				raise ParseError('GotoIf instr with unkown cond {}'.format(self))
			info['cond'] = cond
			pos = parseInt(self.data[2:])
			info['to'] = pos
			desc = ''
			if cond is not None:
				desc = 'if W1 == {} '.format(cond)
			desc += 'goto 0x{:04X}'.format(pos)

		elif self.type == 'return':
			cod = self.data[1:]
			if cod == b'\x20\x00\x00\x00':
				desc = 'generic'
				info['mode'] = 'generic'
			elif cod == b'\x24\x02\x00\x00' or cod == b'\x24\x03\x00\x00':
				desc = 'end program'
				info['mode'] = 'program'
			else:
				raise ParseError('Unexpected return instr {}'.format(self))

		else:
			desc = ''

		return (desc, info)

	def descr(self, const, usages):
		''' Returns instruction's description
		@param const: The constants block in use
		@param usages: The usages list in use
		'''
		base = repr(self)

		try:
			desc, info = self.parse(const, usages)
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
			hx.extend(['  '] * (16-ex))
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

	parser = argparse.ArgumentParser()
	parser.add_argument('ecl_file', help='The compiled script')
	parser.add_argument('-v', '--verbose', action='store_true', help='Show debug output')
	args = parser.parse_args()

	logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

	ecl = ECLFile(args.ecl_file)
	for l in ecl.dump():
		print(l)
	for l in ecl.source():
		print(l)
