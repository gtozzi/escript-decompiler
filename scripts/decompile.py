#!/usr/bin/env python3

'''
EScript decompiler for binary ECL files version 2 (POL093)
'''

import os, sys
import logging
import string
import collections


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

		# Will contain the parsed "use" sections
		self.usages = []
		# Will contain the parsed instructions section
		self.instr = None
		# Will contain the parses constants section
		self.const = None
		# Will contain the program section definition
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

		# Reads sections
		while True:
			try:
				section = self.getNextSection()
			except ParseError as e:
				self.log.critical(e)
				sys.exit(1)

			if isinstance(section, UsageSection):
				self.usages.append(section)
			elif isinstance(section, InstructionsSection):
				if self.instr is not None:
					self.log.critical('Duplicate instructions section found')
					sys.exit(1)
				self.instr = section
			elif isinstance(section, ConstantsSection):
				if self.const is not None:
					self.log.critical('Duplicate constants section found')
					sys.exit(1)
				self.const = section
			elif isinstance(section, ProgramSection):
				if self.program is not None:
					self.log.critical('Duplicate program section found')
					sys.exit(1)
				self.program = section
			else:
				self.log.critical('Unsupported section %s', section)
				sys.exit(1)

			self.pos += 6 + section.size()
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

	def getNextSection(self):
		''' Scans the buffer and returns next section '''
		self.log.info('Looking for a section at pos 0x%X', self.pos)

		sectionHeader = self.buf[self.pos : self.pos+6]
		self.log.debug('Section header %s', sectionHeader)
		code = parseInt(sectionHeader[:2])
		size = parseInt(sectionHeader[2:])
		self.log.info('Found section code %d, declared size %d', code, size)

		if size == 0 and code == 1:
			# Section code 1 doesn't specify a size, go read it from section's data
			size = 13 + int(self.buf[self.pos+6+9]) * 34
			self.log.info('Deduced size of %d bytes for the section', size)
		elif code == 1 and size != 0:
			raise ParseError('Unsupported section code 1 with a given size')
		elif size == 0:
			raise ParseError('Unsupported zero-sized section')

		data = self.buf[self.pos+6 : self.pos+6+size]
		if len(data) != size:
			raise RuntimeError('Data len mismatch')
		self.log.debug('Raw section data: %s', data)

		if code == 1:
			return UsageSection(data)
		elif code == 2:
			return InstructionsSection(data)
		elif code == 3:
			return ConstantsSection(data)
		elif code == 4:
			return ProgramSection(data)
		else:
			raise ParseError('Unsupported section code %d', code)

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
		idx = 0 # Index of next instruction to be read (PC, Program Counter)
		glo = [] # Map of global var IDs => names
		loc = [] # Map of local var IDs => names
		reg = W() # Map of W registers (ValueStack)

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

		# Start program section, if specified
		if self.program:
			parms = []
			# Expect fist instructions to define program variable names
			for i in range(idx,idx+self.program.args):
				inst = self.instr[i]
				desc, info = inst.parse(self.const, self.usages)
				if info['name'] != 'getarg':
					self.log.critical('Assign program instruction expected')
				parms.append(info['arg'])
				loc.append(info['arg'])
			yield('program decompiled(' + ', '.join(parms) + ')')

			blk.append({'type': 'program'})
			idx += self.program.args

		# Parse the instructions
		while idx < len(self.instr):
			inst = self.instr[idx]
			desc, info = inst.parse(self.const, self.usages)

			# End if section if needed
			if blk and blk[-1]['type'] == 'if' and blk[-1]['end'] == idx:
				del blk[-1]
				yield(ind('endif'))

			# Parse next instruction
			try:
				name = info['name']
			except KeyError:
				name = None

			if name == 'run':
				parms = []
				for i in range(info['func'].parm):
					parms.insert(0, reg.pop())
				if len(parms) == 1 and parms[0] == '""':
					parms = [] # Omit a single null string parameter
				call = '{}({})'.format(info['func'].name, ', '.join(parms))
				reg.append(call)

			elif inst.type == 'method':
				reg.append('{}.{}({})'.format(reg[0], name, reg[-1]))

			elif name == 'load':
				if info['var'] and info['scope'] == 'global':
					v = glo[info['id']]
				elif info['var'] and info['scope'] == 'local':
					v = loc[info['id']]
				elif info['type'] == 'str':
					v = quote(info['val'])
				elif info['type'] in ('int','float'):
					v = str(info['val'])
				else:
					self.log.error('unimplemented load')
				reg.append(v)

			elif name == 'assign':
				r = reg.pop()
				l = reg.pop()
				if info['op'] == ':=':
					# Assign left
					res = '{} := {}'.format(l, r)
				elif info['op'] == '.':
					# Access a property
					res = '{}.{}'.format(l, unquote(r))
				elif info['op'] == '+':
					# Concatenation
					res = '{} + {}'.format(l, r)
				else:
					self.log.error('unimplemented assign {op}'.format(**info))
				reg.append(res)

			elif name == 'consume':
				r = reg.pop()
				yield(ind('{};'.format(r)))

			elif name == 'var':
				if info['scope'] == 'global':
					name = 'g' + str(len(glo)+1)
					glo.append(name)
				elif info['scope'] == 'local':
					name = 'l' + str(len(loc)+1)
					loc.append(name)
				else:
					self.log.error('unimplemented var')
				reg.append(name)
				yield(ind('var {};'.format(name)))

			elif inst.type == 'goto':
				if info['cond'] is not None:
					# Conditional jump starts an if section
					op = ''
					if not info['cond']:
						op = '! '
					yield(ind('if( {}{} )'.format(op, reg[0])))
					# Expect to find an unconditional jump at to-1. This jump leads
					# to the end of the "if section"
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

			elif name == 'progend':
				if idx == len(self.instr)-1:
					# This is the final instruction, just ignore it
					pass
				else:
					self.log.error('unimplemented progend')

			elif name == 'blockend':
				# Output registers before deleting them, from left to right
				for i in range(0-info['num'],0):
					yield(ind('{};'.format(reg[i])))
					del reg[i]
				del blk[-1]

			elif name is None:
				self.log.error('unknown instruction {}'.format(inst))

			else:
				self.log.error('unimplemented instruction {}'.format(inst))

			self.log.debug("%02X: %s, W: %s", inst.id, desc, reg)

			idx += 1

class W(collections.UserList):
	''' Holder class for W registers '''
	pass

class Section:
	''' Base class for a generic section '''

	def __init__(self, code, data):
		''' Constructor
		@param code int: The section code
		@param data binary: The RAW section data
		'''
		self.log = logging.getLogger('section')
		self.code = code
		self.data = data

	def size(self):
		''' Returns section length (excluding header) '''
		return len(self.data)


class UsageSection(Section):
	''' A section type 01: "use" directive '''

	def __init__(self, data):
		super().__init__(1, data)
		self.name = parseStr(data[:9], True)
		funcCount = int(data[9])
		if data[10:12] != b'\x00\x00':
			raise ParseError('Unexpected data in bytes 11-13 of section: %s', data[10:12])
		self.func = []
		for i in range(0,funcCount):
			f = data[13+i*34 : 13+i*34+34]
			self.func.append(UsageSectionFunction(f))
		self.log.debug('New usage section %s, functions: %s', self.name, self.func)

	def __str__(self):
		return self.name + ' [' + ', '.join([str(i) for i in self.func]) + ']'

class UsageSectionFunction():
	''' A function inside and usage section '''

	def __init__(self, data):
		self.name = parseStr(data[:33], True)
		self.parm = int(data[33])

	def __repr__(self):
		return self.name + '(' + str(self.parm) + 'p)'


class InstructionsSection(Section):
	''' A section type 02: instructions '''

	def __init__(self, data):
		super().__init__(2, data)
		innerSize = parseInt(data[:4])
		if innerSize != len(data) - 4:
			raise ParseError('Unexpected section inner size')

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

	# Possible values for first byte "type", from tokens.h
	# Often the real meaning is different or this byte is just ignored
	TYPES = (
		'TYP_TERMINATOR',
		'TYP_OPERAND',
		'TYP_OPERATOR', # BINARY implied
		'TYP_UNARY_OPERATOR',
		'TYP_LEFTPAREN',
		'TYP_RIGHTPAREN',
		'TYP_LEFTBRACKET',
		'TYP_RIGHTBRACKET',

		'TYP_TESTMAX', # = TYP_RIGHTBRACKET,

		'TYP_RESERVED',

		'TYP_LABEL', # a GOTO/GOSUB label

		'TYP_FUNC', # func returning something
		'TYP_METHOD', # object method

		'TYP_USERFUNC',

		'TYP_SEPARATOR',
		'TYP_DELIMITER',

		'TYP_CONTROL',

		'TYP_LEFTBRACE',
		'TYP_RIGHTBRACE',

		'TYP_NUMTYPES'
	)

	# Possible values for 2nd byte "id", from tokens.h
	# (commenting out additions for POL099)
	# Comment blocks on the right idicates verified values
	TOKENS = (
		'TOK_LONG',                                                #  0 0x00
		'TOK_DOUBLE',
		'TOK_STRING', # "string literal"

		'TOK_IDENT', # variable identifier, i.e. 'A', 'AB', A$ */

		'TOK_ADD',                                                 #  4 0x04
		'TOK_SUBTRACT',
		'TOK_MULT',
		'TOK_DIV',

		'TOK_ASSIGN',                                              #  8 0x08
		'INS_ASSIGN_CONSUME',

		'TOK_PLUSEQUAL',
		'TOK_MINUSEQUAL',
		#'TOK_TIMESEQUAL',
		#'TOK_DIVIDEEQUAL',
		#'TOK_MODULUSEQUAL',
		'TOK_INSERTINTO',

		# comparison operators
		'TOK_LESSTHAN',
		'TOK_LESSEQ',
		'TOK_GRTHAN',
		'TOK_GREQ',

		'TOK_AND',
		'TOK_OR',

		# equalite/inequality operators
		'TOK_EQUAL',
		'TOK_NEQ',

		# unary operators
		'TOK_UNPLUS',
		'TOK_UNMINUS',
		'TOK_LOG_NOT',
		'TOK_BITWISE_NOT',

		'TOK_CONSUMER',                                            # 25 0x19

		'TOK_ARRAY_SUBSCRIPT',

		'???', # Fllling an hole

		'TOK_ADDMEMBER',
		'TOK_DELMEMBER',
		'TOK_CHKMEMBER',                                           # 30 0x1e

		'CTRL_STATEMENTBEGIN',
		'CTRL_PROGEND',                                            # 32 0x20
		'CTRL_MAKELOCAL',
		'CTRL_JSR_USERFUNC',
		'INS_POP_PARAM',
		'CTRL_LEAVE_BLOCK', # offset is number of variables to remove

		'RSV_JMPIFFALSE',                                          # 37 0x25
		'RSV_JMPIFTRUE',

		'RSV_GOTO',
		'RSV_RETURN',
		'RSV_EXIT',

		'RSV_LOCAL',
		'RSV_GLOBAL',                                              # 43 0x2b
		'RSV_VAR',

		'RSV_FUNCTION',

		'INS_DECLARE_ARRAY',

		'TOK_FUNC',                                                # 47 0x2f
		'TOK_USERFUNC',
		'TOK_ERROR',
		'TOK_IN',
		'TOK_LOCALVAR',
		'TOK_GLOBALVAR',
		'INS_INITFOREACH',
		'INS_STEPFOREACH',
		'INS_CASEJMP',
		'INS_GET_ARG',                                             # 56 0x38
		'TOK_ARRAY',

		'???', # Fllling an hole

		'INS_CALL_METHOD',                                         # 59 0x3b

		'???', # Fllling an hole

		'TOK_DICTIONARY',
		'TOK_STACK',
		'INS_INITFOR',
		'INS_NEXTFOR',
		'TOK_REFTO',
		'INS_POP_PARAM_BYREF',                                     # 66 0x42
		'TOK_MODULUS',

		'TOK_BSLEFT',
		'TOK_BSRIGHT',
		'TOK_BITAND',
		'TOK_BITOR',
		'TOK_BITXOR',

		'TOK_STRUCT',
		'INS_SUBSCRIPT_ASSIGN',
		'INS_SUBSCRIPT_ASSIGN_CONSUME',
		'INS_MULTISUBSCRIPT',
		'INS_MULTISUBSCRIPT_ASSIGN',
		'INS_ASSIGN_LOCALVAR',
		'INS_ASSIGN_GLOBALVAR',

		'INS_GET_MEMBER',
		'INS_SET_MEMBER',
		'INS_SET_MEMBER_CONSUME',

		'INS_ADDMEMBER2',
		'INS_ADDMEMBER_ASSIGN',
		'INS_UNINIT',
		'INS_DICTIONARY_ADDMEMBER',

		'INS_GET_MEMBER_ID',
		'INS_SET_MEMBER_ID',
		'INS_SET_MEMBER_ID_CONSUME',
		'INS_CALL_METHOD_ID',

		'TOK_EQUAL1',

		'INS_SET_MEMBER_ID_CONSUME_PLUSEQUAL',
		'INS_SET_MEMBER_ID_CONSUME_MINUSEQUAL',
		'INS_SET_MEMBER_ID_CONSUME_TIMESEQUAL',
		'INS_SET_MEMBER_ID_CONSUME_DIVIDEEQUAL',
		'INS_SET_MEMBER_ID_CONSUME_MODULUSEQUAL',
	)

	def __init__(self, data):
		self.log = logging.getLogger('instr')
		if len(data) != 5:
			raise ParseError('An instruction must be 5 bytes long')
		self.raw = data

		# Split bits
		self.type = data[0]
		self.id = data[1]
		self.offset = parseInt(data[2:4])
		self.module = data[4]

	def parse(self, const, usages):
		''' Parses this instruction
		@param const: The constants section in use
		@param usages: The usages list in use
		@throws ParseError
		@return list: (readable description, info dictionary (instruction dependant))
		'''
		info = {}

		if self.id == 0x2f:
			info['name'] = 'run'
			uid = int(self.module)
			info['usage'] = usages[uid]
			fid = int(self.type)
			info['func'] = info['usage'].func[fid]
			desc = '{name} {usage.name}:{func}'.format(**info)

		elif self.id == 0x3b:
			info['name'] = 'method'
			info['method'] = const.getStr(pos)
			desc = 'L := R.{method}()'.fotmat(**info)

		elif self.id in (0x00,0x01,0x02, 0x33,0x34):
			info['name'] = 'load'
			if self.id == 0x00:
				info['var'] = False
				info['type'] = 'int'
				info['val'] = const.getInt(self.offset)
			elif self.id == 0x01:
				info['var'] = False
				info['type'] = 'float'
				info['val'] = const.getFloat(self.offset)
			elif self.id == 0x02:
				info['var'] = False
				info['type'] = 'str'
				info['val'] = const.getStr(self.offset)
			elif self.id == 0x33:
				info['var'] = True
				info['scope'] = 'local'
				info['id'] = self.offset
			elif self.id == 0x34:
				info['var'] = True
				info['scope'] = 'global'
				info['id'] = self.offset

			if info['var']:
				desc = 'load {scope} var #{id}'.format(**info)
			else:
				desc = 'load const {type} <{val}>'.format(**info)

		elif self.id == 0x38:
			info['name'] = 'getarg'
			info['arg'] = const.getStr(self.offset)
			desc = '{name} {arg}'.format(**info)

		elif self.id in (0x04,0x05,0x06,0x07, 0x08, 0x1e):
			info['name'] = 'assign'
			space = True
			if self.id == 0x04:
				info['op'] = '+'
			elif self.id == 0x05:
				info['op'] = '-'
			elif self.id == 0x06:
				info['op'] = '*'
			elif self.id == 0x07:
				info['op'] = '/'

			elif self.id == 0x08:
				info['op'] = ':='

			elif self.id == 0x1e:
				info['op'] = '.'
				space = False

			desc = '{name} L := L{s}{op}{s}R'.format(name=info['name'], op=info['op'], s=' ' if space else '')

		elif self.id == 0x19:
			info['name'] = 'consume'
			desc = 'consume R'

		elif self.id in (0x2a, 0x2b):
			info['name'] = 'var'
			if self.id == 0x2b:
				scope = 'global'
			elif self.id == 0x2a:
				scope = 'local'
			info['scope'] = scope
			info['id'] = self.offset
			desc = '{name} {scope} #{id}'.format(**info)

		elif self.id in (0x25, 0x26, 0x27):
			info['name'] = 'goto'
			if self.id == 0x25:
				cond = True
			elif self.id == 0x26:
				cond = False
			elif self.id == 0x27:
				cond = None
			info['cond'] = cond
			info['to'] = self.offset
			if info['cond'] is None:
				cond = ''
			else:
				cond = ' if R == {} (consume R)'.format(info['cond'])
			desc = '{name} 0x{to:04X}{cond}'.format(cond=cond, **info)

		elif self.id == 0x20:
			info['name'] = 'progend'
			desc = 'end program'

		elif self.id == 0x24:
			info['name'] = 'blockend'
			info['num'] = self.offset
			desc = 'end block, del {num} from W'.format(**info)

		else:
			desc = ''

		return (desc, info)

	def descr(self, const, usages):
		''' Returns instruction's description
		@param const: The constants section in use
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
		hx = ' '.join(['{:02X}'.format(c) for c in self.raw])
		return hx + ' - ' + '{:>6s}'.format(self.TOKENS[self.id])


class ConstantsSection(Section):
	''' A section type 03: constants '''

	def __init__(self, data):
		super().__init__(3, data)
		innerSize = parseInt(data[:4])
		if innerSize != len(data) - 4:
			raise ParseError('Unexpected section inner size')

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


class ProgramSection(Section):
	''' A section type 04: program '''

	def __init__(self, data):
		super().__init__(4, data)
		self.args = int(self.data[0])
		if data[1:] != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
			raise ParseError('Unexpected data in bytes 2-16 of section: %s', data[1:])


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
