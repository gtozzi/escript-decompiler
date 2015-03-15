#!/usr/bin/env python3

'''
EScript decompiler for binary ECL files version 2 (POL093)
'''

import os, sys
import struct
import logging
import string
import collections
import re


def parseInt(val):
	''' Parses an int in binary format. First byte is the least significant
	
	The most significant bit of the most significant byte represents the sign (+ if 0, - if 1)
	'''
	if len(val) < 1:
		raise ValueError("Can't parse an empty string")
	if len(val) > 4:
		raise ValueError("Too many bytes for an int")

	while len(val) < 4:
		val += b'\x00'
	ret = struct.unpack('i',val)
	return ret[0]

def parseDouble(val):
	''' Parses a double in binary format '''
	if len(val) != 8:
		raise ValueError("Doubles must be 8 bytes long")

	ret = struct.unpack('d',val)
	return ret[0]

def parseStr(val, fixed=False):
	''' Parses a string in binary format. NULL terminated
	
	@param fixed boolean: If given, makes sure that all the bytes after the NULL terminator are null too
	'''
	ret = b''
	term = False
	for char in val:
		if term and char != 0:
			raise ValueError("Unexpected non-null byte {:02X} after null terminator".format(char))

		if char != 0:
			ret += bytes([char])
		elif fixed:
			term = True
		else:
			break
	try:
		return ret.decode('utf8')
	except UnicodeDecodeError:
		logging.warning('String with non utf8 encoding: %s', ret)
		return ret.decode('iso8859-15')


class ECLFile:

	def __init__(self, inFile):
		self.log = logging.getLogger('eclfile')
		# Buffer where file data will be stored
		self.buf = b''
		# Pointer position counter
		self.pos = 0

		# Will contain ECL version, from header
		self.version = None
		# Will contain number of globals, from header
		self.globals = None
		# Will contain the parsed "use" sections
		self.usages = []
		# Will contain the parsed instructions section
		self.instr = None
		# Will contain the parses constants section
		self.const = None
		# Will contain the program section definition
		self.program = None
		# Will contain the exported functions definition
		self.exports = None

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
				raise e

			if isinstance(section, UsageSection):
				self.usages.append(section)
			elif isinstance(section, InstructionsSection):
				if self.instr is not None:
					self.log.critical('Duplicate instructions section found')
					raise SectionsError('Duplicate instructions section found')
				self.instr = section
			elif isinstance(section, ConstantsSection):
				if self.const is not None:
					self.log.critical('Duplicate constants section found')
					raise SectionsError('Duplicate constants section found')
				self.const = section
			elif isinstance(section, ProgramSection):
				if self.program is not None:
					self.log.critical('Duplicate program section found')
					raise SectionsError('Duplicate program section found')
				self.program = section
			elif isinstance(section, ExportsSection):
				if self.exports is not None:
					self.log.critical('Duplicate exports section found')
					raise SectionsError('Duplicate exports section found')
				self.exports = section
			else:
				self.log.critical('Unsupported section %s', section)
				raise SectionsError('Unsupported section %s' % section)

			self.pos += 6 + section.size()
			if self.pos == len(self.buf):
				# EOF
				break

	def parseHeader(self, header):
		''' Parses the 6 bytes header field '''
		if header[:2] != b'CE':
			raise ParseError('This is not a valid eScript file, wrong magic number')
		self.version = parseInt(header[2:4])
		if self.version != 2:
			raise ParseError('This is not a POL093 eScript file, wrong version number {}'.format(header[2]))
		self.globals = parseInt(header[4:])

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
		elif code == 6:
			return ExportsSection(data)
		else:
			raise ParseError('Unsupported section code %d' % code)

	def dump(self):
		''' return useful informations as a dump
		@return list of lines
		'''
		yield('*** HEADER ***')
		yield('ECL version {}'.format(self.version))
		yield('{} global{}'.format(self.globals, 's' if self.globals != 1 else ''))
		yield('')

		yield('*** USAGES ***')
		i = 0
		for u in self.usages:
			yield('0x{:02X} {}'.format(i, u))
			i += 1
		yield('')

		if self.program:
			yield('*** PROGRAM ***')
			yield('{} argument{}'.format(self.program.args, 's' if self.program.args != 1 else ''))
			yield('')

		yield('*** {} INSTRUCTIONS ***'.format(len(self.instr)))
		for idx, ir in enumerate(self.instr.instr):
			yield('0x{:04X}'.format(idx) + ' - ' + ir.descr(self.const, self.usages))
		yield('')

		yield('*** CONSTANTS ***')
		yield(str(self.const))
		yield('')

		if self.exports:
			yield('*** EXPORTED FUNCTIONS ***')
			for k, f in self.exports.func.items():
				yield(str(f))
			yield('')

	def source(self):
		''' Try to build back the source code for the script
		@return list of lines
		'''

		# Analyze exported functions
		fun = {} # {start idx: {'name', 'args', 'export'}}
		if self.exports is not None:
			for idx, f in self.exports.func.items():
				inst = self.instr[idx+1]
				desc, info = inst.parse(self.const, self.usages)
				if info['name'] != 'function':
					self.log.critical('0x%04X: No function call for exported function found', idx+1)
				fun[info['to']] = {'name': f.name, 'args': f.args, 'export': True}


		# Preparatory step
		used = collections.OrderedDict() # List of used usages, to workaround a compiler bug (see below)
		rep = {} # List of repeat...until blocks { start: end }

		idx = 0
		while idx < len(self.instr):
			inst = self.instr[idx]
			desc, info = inst.parse(self.const, self.usages)

			try:
				name = info['name']
			except KeyError:
				name = None

			# Scan for functions (there is no token for function start)
			if name == 'function':
				if info['to'] not in fun.keys():
					# Found a new function, scan it
					fun[info['to']] = {'name': 'func'+str(info['to']), 'args': 0, 'export': False}
					idf = info['to']
					while idf < len(self.instr):
						ins = self.instr[idf]
						des, inf = ins.parse(self.const, self.usages)
						try:
							nam = inf['name']
						except KeyError:
							nam = None

						if nam == 'return':
							break
						elif nam == 'poparg':
							fun[info['to']]['args'] += 1

						idf += 1

			# Scan for start of repeat...until blocks
			if name == 'goto' and info['cond'] is not None and info['to'] < idx:
				rep[info['to']] = idx

			# Scan for used functions (outputs unused below)
			elif name == 'run':
				if not info['func'] in used.keys():
					# Will use this later to output unused functions
					used[info['func']] = idx

			idx += 1

		# Determine functions output order { func : min index }
		funcOrder = collections.OrderedDict()
		for u in self.usages:
			for i in range(0,len(u.func)):
				cur = u.func[i]
				before = [u.func[k] for k in range(0,i)]
				idx = 0
				for b in before:
					if b in used.keys() and used[b] > idx:
						idx = used[b]
				funcOrder[cur] = idx


		self.log.debug('Functions: %s', fun)
		self.log.debug('Repeat blocks: %s', rep)

		# Output header
		yield('// Source decompiled from binary using decompile.py')
		yield('// written by Scripter Bodom @ ZHI Time Warp shard <bodom@discosucks.it>')
		yield('// with the precious help of Scripter Evolution, from the same shard')
		yield('')

		# Registers and status variables
		blk = [] # Last block is the current block, also used as indentation level
		idx = 0 # Index of next instruction to be read (PC, Program Counter)
		glo = [] # Map of global var IDs => names
		reg = W() # Map of W registers (original is a ValueStack: http://it.cppreference.com/w/cpp/container/deque)

		# Utility functions and vars
		ops = {
			':=': 50,
			'=':  40,
			'>=': 40,
			'>':  40,
			'<=': 40,
			'<':  40,
			'!=': 40,
			'in': 40,
			'&&': 30,
			'||': 30,
			'&':  26,
			'^':  24,
			'|':  22,
			'*':  20,
			'/':  20,
			'%':  20,
			'-':  10,
			'+':  10,
		}
		def ind(row, mod=0):
			''' adds indentation to a row '''
			tabs = '\t' * (len(blk)+mod)
			return tabs + row.replace('\t', tabs + '\t')
		def quote(string):
			''' quotes a string '''
			return '"{}"'.format(string.replace('"', '\\"'))
		def unquote(string):
			''' removes quotes from a quoted string '''
			if string[0] == '"' and string[-1] == '"':
				return string[1:-1].replace('\\"', '"')
			return string
		def getParms(num):
			''' retrieves num params from W '''
			parms = []
			for i in range(num):
				parms.insert(0, reg.pop())
			return parms
		def enclose(left, op, right):
			''' add parenthesys if needed '''
			exRe = re.compile('\(.*\)')
			left = str(left)
			right = str(right)

			# Calculate left, right, and operator power
			opow = ops[op]
			lpow = 100
			l = exRe.sub('', left)
			for o in ops.keys():
				if l.find(o) != -1 and ops[o] < lpow:
					lpow = ops[o]
			rpow = 100
			r = exRe.sub('', right)
			for o in ops.keys():
				if r.find(o) != -1 and ops[o] < rpow:
					rpow = ops[o]

			if lpow < opow:
				left = '({})'.format(left)

			if rpow <= opow:
				right = '({})'.format(right)

			return left, right
		def encloseAny(val):
			''' add parenthesys if any operator is detected inside the string '''
			if not isinstance(val, str):
				return val
			for o in list(ops.keys()) + ['.']:
				if val.find(o) != -1:
					return '({})'.format(val)
			return val
		def dummyFunction(unused, suffix):
			# Outputs unused usages: since the compiler is purging unused functions but
			# not unused usages (from the usages section), this is necessary to make
			# the binary compiled from the decompiled source identical to the original
			# one
			yield('')
			yield('')
			yield('// Dummy function, this is never invoked')
			yield('// This is necessary to make the compiled decompiled source binary equal')
			yield('// to original because of a bug in the compiler (optimizer). This can be')
			yield('// safely deleted without any effect on the code execution')
			yield('function decompiler_dummy_function_{}(p)'.format(suffix))
			for f in unused:
				yield('\t{}({});'.format(f.name, ', '.join(['p'] * f.parm)))
			yield('endfunction')
			yield('')

		# Start with usages
		for u in self.usages:
			if u.name not in ('basic','basicio'):
				yield('use {};'.format(u.name))
		yield('')

		# Parse the instructions
		progParms = None # Will contain parameters for program block until they are outputted
		curFunc = None # Will contain parameters for user function block until outputted
		progStarted = False # Will be true when program block has been started
		lastCase = None # Will store when last "case" statement has been printed

		while idx < len(self.instr):
			inst = self.instr[idx]
			desc, info = inst.parse(self.const, self.usages)

			# End if sections if needed
			while blk and blk[-1].type == 'if' and blk[-1].end == idx:
				del blk[-1]
				yield(ind('endif'))

			# Parse next instruction
			try:
				name = info['name']
			except KeyError:
				name = None

			# Outputs dummy function if needed (see above)
			outUnused = []
			for f, i in funcOrder.items():
				if i >= idx and ( name != 'run' or info['func'] != f ):
					outUnused.append(f)
			if outUnused:
				yield from dummyFunction(outUnused, str(idx))
			for o in outUnused:
				del funcOrder[o]

			if progParms is not None and name != 'getarg':
				# Parameters are over: outputs program directive
				yield('program decompiled(' + ', '.join(progParms) + ')')
				progParms = None
				progStarted = True

			if self.program is not None and self.program.args == 0 and not progStarted and not blk and ((name == 'var' and info['scope'] == 'local') or name == 'consumer'):
				# I know i have a program block, but no params will be passed
				# so I need to do some guessing to figure out where it will start.
				# Will start it before first local variable is declared or before
				# first consumer
				yield('program decompiled()')
				blk.append(Block('program', blk, idx))
				progStarted = True

			if idx in fun.keys():
				# Close any opened block and start the function
				for i in range(0,len(blk)):
					yield(ind('end{}'.format(blk[-1].type), -1))
					if blk[-1].type in ('program', 'function'):
						yield('')
					del blk[-1]
				curFunc = fun[idx]
				curFunc['parms'] = []
				blk.append(Block('function', None, idx))

			if curFunc is not None and name != 'poparg':
				# Outputs user function directive
				p = reversed([ ('byref ' if i['byref'] else '') + i['arg'] for i in curFunc['parms'] ])
				e = 'exported ' if curFunc['export'] else ''
				yield('{}function {}('.format(e, curFunc['name']) + ', '.join(p) + ')')
				curFunc = None

			if blk and blk[-1].type == 'case':
				# Output case statement if needed
				for v, i in blk[-1].cases.items():
					if i == idx:
						blk[-1].resetVars()
						if v is None:
							c = 'default'
							if blk[-1].end is None and idx != blk[-1].start + 1 and idx == max(blk[-1].cases.values()):
								# Case probably ends here
								del blk[-1]
								yield(ind('endcase'))
								continue
							elif blk[-1].end == idx:
								# Don't output empty default case at the end of the block
								ide, iin = self.instr[idx-1].parse(self.const, self.usages)
								if iin['name'] == 'goto' and iin['cond'] is None and iin['to'] == idx and lastCase != idx:
									# There is an empty case at the end of the case block and no
									# case statemente has still been outputted yet
									pass
								else:
									continue
						elif isinstance(v, int):
							c = v
						elif isinstance(v, str):
							c = quote(v)
						else:
							raise RuntimeError('Unexpected type {} for case'.format(type(v)))
						yield(ind('{}:'.format(c),-1))
						lastCase = idx

			if blk and blk[-1].type == 'case':
				# Output endcase when end reached
				if blk[-1].end is not None and blk[-1].end == idx:
					del blk[-1]
					yield(ind('endcase'))
					lastCase = None

			# End if sections if needed (check again after eventually ending some case blocks)
			# FIXME: avoid duplicated code
			while blk and blk[-1].type == 'if' and blk[-1].end == idx:
				del blk[-1]
				yield(ind('endif'))

			if idx in rep.keys():
				# Starts repeat...ultil block if needed
				b = Block('repeat', blk, idx)
				b.end = rep[idx]
				yield(ind('repeat'))
				blk.append(b)


			if name == 'getarg':
				if not len(blk) or blk[-1].type != 'program':
					# Auto-starting program block
					progParms = []
					blk.append(Block('program', blk, idx))
				progParms.append(info['arg'])
				blk[-1].vars.append(info['arg'])

			elif name == 'poparg':
				curFunc['parms'].append(info)
				blk[-1].vars.append(info['arg'])

			elif name == 'run':
				if info['func'] in funcOrder.keys():
					del funcOrder[info['func']]
				parms = getParms(info['func'].parm)
				if len(parms) == 1 and parms[0] == '""':
					parms = [] # Omit a single null string parameter
				call = '{}({})'.format(info['func'].name, ', '.join([str(p) for p in parms]))
				reg.append(call)

			elif name == 'method':
				parms = getParms(info['parm'])
				r = encloseAny(reg.pop())
				reg.append('{}.{}({})'.format(r, info['method'], ', '.join([str(p) for p in parms])))

			elif name == 'makelocal':
				# "Prepare" parameters for next function call, try to just ignore it
				# and do all the job on the call
				pass

			elif name == 'function':
				parms = []
				for i in range(0,fun[info['to']]['args']):
					parms.insert(0, reg.pop())
				reg.append('{}({})'.format(fun[info['to']]['name'], ', '.join([str(p) for p in parms])))

			elif name == 'load':
				if info['var'] and info['scope'] == 'global':
					v = glo[info['id']]
				elif info['var'] and info['scope'] == 'local':
					v = blk[-1].vars[info['id']]
				elif info['type'] == 'str':
					v = quote(info['val'])
				elif info['type'] in ('int','double'):
					v = str(info['val'])
				elif info['type'] == 'error':
					v = 'error'
				else:
					self.log.error('0x%04X: unimplemented load', idx)
				reg.append(v)

			elif name == 'assign':
				r = reg.pop()
				l = reg.pop()

				if info['op'] == ':=':
					# Assign left
					res = '{} := {}'.format(l, r)
				elif info['op'] == ':=&':
					# Assign byRef
					res = '{} := {}'.format(l, r)
					yield(ind("{};".format(res)))
				elif info['op'] == '.':
					# Access a property
					r = encloseAny(r)
					if r[0] != '(':
						r = unquote(r)
					res = '{}.{}'.format(l, r)
				elif info['op'] in ('+', '-', '*', '/', '%'):
					# Arithmetic: concatenation/addition, subtraction, multiplication, division, modulus
					l, r = enclose(l, info['op'], r)
					res = '{} {} {}'.format(l, info['op'], r)
				elif info['op'] in ('&', '|', '^'):
					# Bitwise: and, or, xor
					l, r = enclose(l, info['op'], r)
					res = '{} {} {}'.format(l, info['op'], r)
				elif info['op'] in ('&&', '||'):
					# Logical: and, or
					l, r = enclose(l, info['op'], r)
					res = '{} {} {}'.format(l, info['op'], r)
				elif info['op'] in ('=', '!=', '<','<=','>','>=', 'in'):
					# Comparison: equal, not equal, lesser than, lesser or equal than,
					#             greater than, greater or equal than, in array
					l, r = enclose(l, info['op'], r)
					res = '{} {} {}'.format(l, info['op'], r)
				elif info['op'] == '[]':
					# Array subscription
					if info['idx'] == 0:
						res = '{}[{}]'.format(l, r)
					elif info['idx'] > 0:
						if not l.endswith(']'):
							self.log.critical('0x%04X: multiple subscription on a non-array %s', idx, info)
						res = '{},{}]'.format(l[:-1], r)
					else:
						self.log.error('0x%04X: unimplemented array subscription %s', idx, info)
				elif info['op'] in ('.+', '.-'):
					# Array add member, array del member
					res = '{}{}{}'.format(l, info['op'], unquote(r))
				else:
					self.log.error('0x%04X: unimplemented assign %s', idx, info['op'])
				reg.append(res)

			elif name == 'unary':
				r = reg.pop()
				if info['op'] in ('+','-','!'):
					res = '{} {}'.format(info['op'], encloseAny(r))
				else:
					self.log.error('0x%04X: unimplemented unary %s', idx, info['op'])
				reg.append(res)

			elif name == 'array':
				if info['act'] == 'start':
					reg.append(Array())
				elif info['act'] == 'append':
					val = reg.pop()
					reg[-1].append(val)
				else:
					self.log.error('0x%04X: unimplemented array %s', idx, info['act'])

			elif name == 'struct':
				reg.append(Struct())

			elif name == 'dict':
				reg.append(Dict())

			elif name == 'consume':
				r = reg.pop()
				yield(ind('{};'.format(r)))

			elif name == 'var':
				# checks if next instrction inits variable as array
				nd, ni = self.instr[idx+1].parse(self.const, self.usages)
				try:
					if ni['name'] == 'vararr':
						array = True
					else:
						array = False
				except KeyError:
					# Next instruction is unknown
					array = False

				if info['scope'] == 'global':
					name = 'g' + str(info['id']+1) #str(len(glo)+1)
					glo.append(name)
				elif info['scope'] == 'local':
					name = 'l'*len(blk) + str(info['id']+1) #str(len(loc)+1)
					blk[-1].vars.append(name)
				else:
					self.log.error('0x%04X: unimplemented var', idx)
				reg.append(name)
				yield(ind('var {}{};'.format(name, ' array' if array else '')))

			elif name == 'vararr':
				# Ignore it now because it has already been processed by var
				pass

			elif name == 'goto':
				# A goto may be part of an if block or of a loop (for/while)
				# proceed with some logical analysis and guessing
				if info['cond'] is not None and info['to'] > idx:
					# Conditional forward jump starts an if or while section
					# Expect to find an unconditional jump at to-1. This jump leads
					# to the end of the "if section" on an if block or back to the
					# block definition in a while block
					op = '! ' if info['cond'] else ''
					to = self.instr[info['to']-1]
					toDescr, toInfo = to.parse(self.const, self.usages)
					elseInstr = None
					end = info['to']
					if toInfo['name'] == 'goto' and toInfo['cond'] is None:
						# This could be the "else" statement on an if or the jump back
						# on a while
						if toInfo['to'] > info['to']:
							# Jumping forward: this could be an else statement
							obstacle = False
							forOpen = 0
							for b in blk:
								# Safety check: don't confuse an else with a break
								# an else jump sould be inside the end of any parent block
								try:
									if b.end is not None and ( toInfo['to'] > b.end or toInfo['to'] == b.end and b.type != 'if' ):
										obstacle = True
										break
								except AttributeError:
									continue
							if not obstacle:
								for i in range(info['to'], toInfo['to']):
									# Safety check: don't confuse an else with a break out of foreach
									ide, iin = self.instr[i].parse(self.const, self.usages)
									if iin['name'] == 'foreach':
										if iin['act'] == 'start':
											forOpen += 1
										elif iin['act'] == 'step' and forOpen > 0:
											forOpen -= 1
										elif iin['act'] == 'step':
											obstacle = True
											break
							if not obstacle:
								# Safety check: jump leading exactly to a step foreach is a continue
								ide, iin = self.instr[toInfo['to']].parse(self.const, self.usages)
								if iin['name'] == 'foreach' and iin['act'] == 'step':
									obstacle = True
							if not obstacle:
								elseInstr = info['to'] - 1
								gd, gi = to.parse(self.const, self.usages)
								end = gi['to']
							typ = 'if'
						elif toInfo['to'] <= idx and ( not blk or toInfo['to'] > blk[-1].start ):
							# Jumping backward but not too much
							# this could be the endwhile statement
							typ = 'while'
						else:
							# This should be a "continue" statement of a parent while block,
							# trying to confuse us.
							# Just ignore it for the moment and start a standard if block
							typ = 'if'
					else:
						# No mathing jump found, this is a simple if block
						typ = 'if'
					yield(ind('{}( {}{} )'.format(typ, op, encloseAny(reg.pop()) if op else reg.pop())))
					b = Block(typ, blk, idx)
					if typ == 'if':
						b.els = elseInstr
					b.end = end
					blk.append(b)
				elif info['cond'] is not None and info['to'] < idx:
					# Conditional backward jump ends a repeat...until block
					if blk[-1].type != 'repeat' or blk[-1].end != idx:
						self.log.critical('0x%04X: unexpected until statement (block: %s)', idx, blk[-1])
					op = '! ' if info['cond'] else ''
					del blk[-1]
					yield(ind('until( {}{} );'.format(op, encloseAny(reg.pop()) if op else reg.pop())))
				elif info['cond'] is None and blk and blk[-1].type == 'if' and blk[-1].els == idx:
					# This is the else jump of the current "if" statement
					blk[-1].resetVars()
					yield(ind('else',-1))
				elif info['cond'] is None and blk and blk[-1].type == 'while' and blk[-1].end-1 == idx:
					# This is the end jump of the current "while" statement
					yield(ind('endwhile',-1))
					del blk[-1]
				elif info['cond'] is None and blk and blk[-1].type == 'case' and idx+1 in blk[-1].cases.values():
					# Jumps out of the case block, every goto should have the same "to"
					if blk[-1].end is None:
						blk[-1].end = info['to']
					elif blk[-1].end != info['to']:
						self.log.error('0x%04X: unexpected case goto (block: %s)', idx, blk[-1])
				elif info['cond'] is None and blk and info['to'] < blk[-1].start:
					# Jumps backwards before current block start, should be a "continue" statement
					yield(ind('continue;'))
				elif info['cond'] is None and blk and hasattr(blk[-1],'end') and blk[-1].end is not None and info['to'] > blk[-1].end:
					# Jumps forward after current block end, should be a "break" statement
					ide, iin = self.instr[info['to']].parse(self.const, self.usages)
					if iin['name'] == 'foreach' and iin['act'] == 'step':
						# Jumpt exactly on a foreach step statement, should be a "continue" instead
						yield(ind('continue;'))
					else:
						yield(ind('break;'))
				elif info['cond'] is None and blk and blk[-1].type == 'case':
					# This should be a "break" statement for a case block
					yield(ind('break;'))
				else:
					self.log.error('0x%04X: unimplemented goto (block: %s)', idx, blk[-1])

			elif name == 'foreach':
				if info['act'] == 'start':
					what = reg.pop()
					b = Block('foreach', blk, idx)
					it = Iterator(len(blk))
					b.vars.append(it)
					b.vars.append(what)
					b.vars.append(str(it))
					reg.append(it)
					reg.append(what)
					reg.append(str(it))
					l = reg[-1]
					r = reg[-2]
					if r.find(']') != -1 or r.find('[') != -1:
						r = '({})'.format(r)
					for o in list(ops.keys()) + ['.']:
						if r.find(o) != -1:
							r = '( {} )'.format(r)
							break;
					yield(ind('foreach {} in {}'.format(l, r)))
					blk.append(b)
				elif info['act'] == 'step':
					if blk[-1].type != 'foreach':
						self.log.critical('0x%04X: stepforeach outside of foreach block', idx)
					del blk[-1]
					yield(ind('endforeach'))
				else:
					self.log.error('0x%04X: unimplemented foreach', idx)

			elif name == 'for':
				if info['act'] == 'start':
					l = reg[-2]
					r = reg[-1]
					b = Block('for', blk, idx)
					it = Iterator(len(blk))
					b.vars.append(it)
					reg.append(it)
					yield(ind('for {} := {} to {}'.format(it, l, r)))
					blk.append(b)
				elif info['act'] == 'step':
					# Just ignore it
					pass
				else:
					self.log.error('0x%04X: unimplemented foreach', idx)

			elif name == 'case':
				yield(ind('case( {} )'.format(reg.pop())))
				b = Block('case', blk, idx)
				b.cases = info['cases']
				b.end = None # End is unknown at the moment, first goto will tell it
				blk.append(b)

			elif name == 'progend':
				if idx == len(self.instr) - 1 or idx + 1 in fun.keys():
					# This is the final instruction, just ignore it
					yield('')
				else:
					# This is a return out of the program block
					yield(ind('return{};'.format(' '+reg[-1] if len(reg) else '')))

			elif name == 'exit':
				yield(ind('exit;'))

			elif name == 'blockend':
				# Output registers before deleting them, from left to right
				for i in range(0-info['num'],0):
					try:
						del reg[i]
					except IndexError:
						self.log.warning('0x%04X: unable to consume index %s', idx, i)

				if len(blk) and blk[-1].type in ('while', 'if', 'foreach', 'program', 'function', 'repeat', 'case'):
					# Do not end blocks ended automatically
					pass
				elif len(blk):
					yield(ind("end{}".format(blk[-1].type), -1))
					del blk[-1]
				else:
					self.log.warning('No block to end')

			elif name == 'return':
				yield(ind('return {};'.format(reg.pop())))

			elif name is None:
				self.log.error('0x%04X: unknown instruction %s', idx, inst)

			else:
				self.log.error('0x%04X: unimplemented instruction %s', idx, inst)


			self.log.debug("0x%04X: %s, W: %s", idx, desc, reg)

			idx += 1

		# Ends any remaining block
		for i in range(len(blk)-1,-1,-1):
			yield(ind("end{}".format(blk[i].type), -1))
			if blk[i].type == 'program':
				yield('')
			del blk[i]

		# Outputs program block if it still has not been started yet.
		# Looks like it doesn't make any difference in the final binary compiled file
		if self.program is not None and not progStarted:
			yield('')
			yield('// Decompiler couldn\'t find program block start, so it\'s placing it here')
			yield('// Looks like it doesn\'t make any difference in the compiled version anyway...')
			yield('program decompiled()')
			yield('endprogram')
			yield('')
			progStarted = True

		# Outputs dummy function if needed (see above)
		if len(funcOrder):
			yield from dummyFunction(funcOrder, 'last')


	def optimize(self, source):
		''' Optimizes a built source '''
		src = list(source)
		ret = src[:]

		varRe = re.compile('^(?P<ind>\s*)(?P<var>[lg]+[0-9]+);$')
		valRe = re.compile('^(?P<ind>\s*)var (?P<var>[a-z0-9]+);$')
		assignRe = re.compile('^(?P<ind>\s*)(?P<var>[a-z0-9]+) := (?P<ass>.+)$', re.M)
		whileRe = re.compile('^(?P<ind>\s*)while\( (?P<var>[a-z0-9]+) (?P<cond>.*) \)$')
		endwhileRe = re.compile('^(?P<ind>\s*)endwhile$')
		elseRe = re.compile('^(?P<ind>\s*)else$')
		ifRe = re.compile('^(?P<ind>\s*)if\( (?P<cond>.*) \)$')
		endifRe = re.compile('^(?P<ind>\s*)endif$')

		i = -1
		for line in src:
			i += 1

			# Merge together variable declaration and next assignment
			assign = assignRe.match(line)
			if assign:
				val = valRe.match(src[i-1])
				if val and assign.group('var') == val.group('var'):
					ret[i] = assign.group('ind') + 'var ' + src[i].strip()
					ret[i-1] = None

		# Remove emptied lines
		ret = [ i for i in ret if i is not None ]

		# Loop until at least one block is converted
		found = True
		while found:
			found = False
			i = -1
			src = ret[:]
			for line in src:
				i += 1

				# Convert first while into for loop
				whil = whileRe.match(line)
				if whil:
					pre = assignRe.match(src[i-1])
					if not pre:
						pre = varRe.match(src[i-1])

					if pre and whil.group('var') == pre.group('var'):
						k = i
						while True:
							k += 1
							ew = endwhileRe.match(src[k])
							if ew and ew.group('ind') == whil.group('ind'):
								end = k
								break
						ass2 = assignRe.match(src[end-1])
						if ass2 and ass2.group('ass').find(ass2.group('var')) != -1:
							ret[i] = whil.group('ind') + 'for( {} {} {}; {} )'.format(src[i-1].strip(), whil.group('var'), whil.group('cond'), src[end-1].strip().rstrip(';'))
							ret[i-1] = None
							ret[end-1] = None
							ret[end] = ew.group('ind') + 'endfor'

							found = True
							break

			# Remove emptied lines
			ret = [ i for i in ret if i is not None ]

		i = -1
		src = ret[:]
		for line in src:
			i += 1

			# Remove lines with variable names only
			var = varRe.match(line)
			if var:
				ret[i] = None

		# Remove emptied lines
		ret = [ i for i in ret if i is not None ]

		def ifElseToElseIf(ret):
			i = 0
			found = 0
			while i < len(ret):
				# Convert nested if/else blocks in elseif blocks
				els = elseRe.match(ret[i])
				if els:
					k = i
					while k < len(ret):
						endif = endifRe.match(ret[k])
						if endif and endif.group('ind') == els.group('ind'):
							end = k
							break
						k += 1
					ifr = ifRe.match(ret[i+1])
					if ifr:
						k = i+1
						while k < len(ret):
							endif = endifRe.match(ret[k])
							if endif and endif.group('ind') == ifr.group('ind'):
								endr = k
								break
							k += 1
						if endr == end - 1:
							found += 1
							ret[i] = ret[i] + ret[i+1].strip()
							ret[i+1] = None
							i += 1
							while True:
								i += 1
								er = endifRe.match(ret[i])
								ret[i] = ret[i][1:]
								if er and er.group('ind') == ifr.group('ind'):
									ret[i] = None
									break
				i += 1

			# Remove emptied lines
			ret = [ i for i in ret if i is not None ]

			if found:
				ret = ifElseToElseIf(ret)

			return ret

		ret = ifElseToElseIf(ret)

		return ret

class W(collections.UserList):
	''' Holder class for W registers '''
	pass

class Block():
	''' This represents an indentation/scope block '''
	def __init__(self, type, blocks, start):
		self.type = type
		self.start = start
		if blocks is not None and len(blocks):
			# Copy vars from parent
			self.vars = blocks[-1].vars[:]
		else:
			self.vars = []
		self.startVars = self.vars[:]
	def resetVars(self):
		''' Sets self.vars back to its initial value '''
		self.vars = self.startVars[:]
	def __repr__(self):
		return '<Block {}>'.format(self.__dict__)

class Array(collections.UserList):
	''' Utility class to represent an array '''
	def __str__(self, ind=0):
		ret = '{'
		if len(self):
			ret += os.linesep
		for v in self:
			ret += '\t'*(ind+1) + str(v) + ',' + os.linesep
		if len(self):
			ret += '\t'*ind
		ret += '}'
		return ret

class Struct(Array):
	''' Utility class to represent a structure (associative array)
	Derived from array because it will always be empty (no append token)
	and and empty structure is represented just like an ampty array
	'''
	def __str__(self):
		if not len(self):
			return 'struct'
		return super().__str__()

class Dict(Struct):
	''' Utility class to represent a dictionary '''
	def __str__(self):
		if not len(self):
			return 'dictionary'
		return super().__str__()

class Iterator():
	''' This represents an iterator '''
	def __init__(self, depth):
		self.depth = depth
	def __repr__(self):
		return '<Iterator #{}>'.format(self.depth)
	def __str__(self):
		return 'key{}'.format(self.depth)

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
		'TOK_LESSTHAN',                                            # 13 0x0d
		'TOK_LESSEQ',
		'TOK_GRTHAN',
		'TOK_GREQ',

		'TOK_AND',                                                 # 17 0x11
		'TOK_OR',

		# equalite/inequality operators
		'TOK_EQUAL',                                               # 19 0x13
		'TOK_NEQ',

		# unary operators
		'TOK_UNPLUS',
		'TOK_UNMINUS',
		'TOK_LOG_NOT',                                             # 23 0x17
		'TOK_BITWISE_NOT',

		'TOK_CONSUMER',                                            # 25 0x19

		'TOK_ARRAY_SUBSCRIPT',                                     # 26 0x1a

		'TOK_ADDMEMBER',                                           # 27 0x1b
		'TOK_DELMEMBER',

		'???', # Fllling an hole

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
		'RSV_RETURN',                                              # 40 0x28
		'RSV_EXIT',

		'RSV_LOCAL',
		'RSV_GLOBAL',                                              # 43 0x2b
		'RSV_VAR',

		'RSV_FUNCTION',

		'INS_DECLARE_ARRAY',                                       # 46 0x2e

		'TOK_FUNC',                                                # 47 0x2f
		'TOK_USERFUNC',
		'TOK_ERROR',                                               # 49 0x31
		'TOK_IN',
		'TOK_LOCALVAR',
		'TOK_GLOBALVAR',
		'INS_INITFOREACH',                                         # 53 0x35
		'INS_STEPFOREACH',
		'INS_CASEJMP',
		'INS_GET_ARG',                                             # 56 0x38

		'TOK_ARRAY_APPEND', # Just guessing
		'TOK_ARRAY',                                               # 58 0x3a

		'INS_CALL_METHOD',                                         # 59 0x3b

		'TOK_DICTIONARY',                                          # 60 0x3c
		'TOK_STACK',
		'INS_INITFOR',                                             # 62 0x3e
		'INS_NEXTFOR',                                             # 63 0x3f

		'???', # Fllling an hole

		'TOK_REFTO',                                               # 65 0x41
		'INS_POP_PARAM_BYREF',                                     # 66 0x42
		'TOK_MODULUS',                                             # 67 0x43

		#'TOK_BSLEFT',
		#'TOK_BSRIGHT',
		'TOK_BITAND',
		'TOK_BITOR',
		'TOK_BITXOR',                                              # 70 0x46

		'TOK_STRUCT',                                              # 71 0x47
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
			info['method'] = const.getStr(self.offset)
			info['parm'] = self.type
			desc = 'L := R.{method}()'.format(**info)

		elif self.id == 0x21:
			info['name'] = 'makelocal'
			desc = '{name}'.format(**info)

		elif self.id == 0x22:
			info['name'] = 'function'
			info['to'] = self.offset
			desc = 'call function at 0x{to:04X}'.format(**info)

		elif self.id in (0x23, 0x41):
			info['name'] = 'poparg'
			info['arg'] = const.getStr(self.offset)
			info['byref'] = True if self.id == 0x41 else False
			desc = '{name} {arg}{byref}'.format(name=info['name'], arg=info['arg'], byref=' byref' if info['byref'] else '')

		elif self.id in (0x00,0x01,0x02, 0x31, 0x33,0x34):
			info['name'] = 'load'
			if self.id == 0x00:
				info['var'] = False
				info['type'] = 'int'
				info['val'] = const.getInt(self.offset)
			elif self.id == 0x01:
				info['var'] = False
				info['type'] = 'double'
				info['val'] = const.getDouble(self.offset)
			elif self.id == 0x02:
				info['var'] = False
				info['type'] = 'str'
				info['val'] = const.getStr(self.offset)
			elif self.id == 0x31:
				info['var'] = False
				info['type'] = 'error'
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
				if info['type'] == 'error':
					desc = 'load const error'
				else:
					desc = 'load const {type} <{val}>'.format(**info)

		elif self.id == 0x38:
			info['name'] = 'getarg'
			info['arg'] = const.getStr(self.offset)
			desc = '{name} {arg}'.format(**info)

		elif self.id in (0x04,0x05,0x06,0x07, 0x08, 0x0d,0x0e,0x0f,0x10, 0x11,0x12, 0x13,0x14, 0x1a,0x1b,0x1c, 0x1e, 0x32, 0x42, 0x43, 0x44,0x45,0x46):
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

			elif self.id == 0x0d:
				info['op'] = '<'
			elif self.id == 0x0e:
				info['op'] = '<='
			elif self.id == 0x0f:
				info['op'] = '>'
			elif self.id == 0x10:
				info['op'] = '>='

			elif self.id == 0x11:
				info['op'] = '&&'
			elif self.id == 0x12:
				info['op'] = '||'

			elif self.id == 0x13:
				info['op'] = '='
			elif self.id == 0x14:
				info['op'] = '!='

			elif self.id == 0x1a:
				info['op'] = '[]'
				info['idx'] = self.offset
				space = False
			elif self.id == 0x1b:
				info['op'] = '.+'
				space = False
			elif self.id == 0x1c:
				info['op'] = '.-'
				space = False

			elif self.id == 0x1e:
				info['op'] = '.'
				space = False

			elif self.id == 0x32:
				info['op'] = 'in'

			elif self.id == 0x42:
				info['op'] = ':=&'

			elif self.id == 0x43:
				info['op'] = '%'

			elif self.id == 0x44:
				info['op'] = '&'
			elif self.id == 0x45:
				info['op'] = '|'
			elif self.id == 0x46:
				info['op'] = '^'

			desc = '{name} L := L{s}{op}{s}R'.format(name=info['name'], op=info['op'], s=' ' if space else '')

		elif self.id in (0x15,0x16,0x17):
			info['name'] = 'unary'
			if self.id == 0x15:
				info['op'] = '+'
			if self.id == 0x16:
				info['op'] = '-'
			if self.id == 0x17:
				info['op'] = '!'
			desc = '{name} R := {op} R'.format(**info)

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

		elif self.id == 0x2e:
			info['name'] = 'vararr'
			desc = 'init var as array'

		elif self.id in (0x25, 0x26, 0x27):
			info['name'] = 'goto'
			if self.id == 0x25:
				cond = False
			elif self.id == 0x26:
				cond = True
			elif self.id == 0x27:
				cond = None
			info['cond'] = cond
			info['to'] = self.offset
			if info['cond'] is None:
				cond = ''
			else:
				cond = ' if R == {} (consume R)'.format(info['cond'])
			desc = '{name} 0x{to:04X}{cond}'.format(cond=cond, name=info['name'], to=info['to'])

		elif self.id == 0x28:
			info['name'] = 'return'
			desc = 'return from user func'

		elif self.id in (0x35, 0x36):
			info['name'] = 'foreach'
			if self.id == 0x35:
				info['act'] = 'start'
			elif self.id == 0x36:
				info['act'] = 'step'
			desc = '{act} {name}'.format(**info)

		elif self.id in (0x3e, 0x3f):
			info['name'] = 'for'
			if self.id == 0x3e:
				info['act'] = 'start'
			elif self.id == 0x3f:
				info['act'] = 'step'
			desc = '{act} {name}'.format(**info)

		elif self.id == 0x37:
			info['name'] = 'case'
			info['cases'] = collections.OrderedDict()
			i = self.offset
			while True:
				idx = const.getShort(i)
				n = const.getByte(i+2)
				if n == 0xfe:
					# This is the last case (default)
					info['cases'][None] = idx
					break
				elif n == 0xff:
					# This is an integer case, more cases to be read
					val = const.getInt(i + 3)
					s = 4
				elif n > 0x00 and n < 0xfe:
					# This is a string case
					val = const.getStr(i + 3, len=n)
					s = n
				else:
					raise ValueError('Unexpected case byte {:02X}'.format(n))
				info['cases'][val] = idx
				i += 3 + s
			desc = 'case jump ({} cases)'.format(len(info['cases']))

		elif self.id == 0x20:
			info['name'] = 'progend'
			desc = 'end program'

		elif self.id == 0x24:
			info['name'] = 'blockend'
			info['num'] = self.offset
			desc = 'end block, del {num} from W'.format(**info)

		elif self.id == 0x29:
			info['name'] = 'exit'
			desc = 'exit'

		elif self.id in (0x39, 0x3a):
			info['name'] = 'array'
			if self.id == 0x39:
				info['act'] = 'append'
			elif self.id == 0x3a:
				info['act'] = 'start'
			desc = '{name} {act}'.format(**info)

		elif self.id == 0x47:
			info['name'] = 'struct'
			desc = 'struct start'

		elif self.id == 0x3c:
			info['name'] = 'dict'
			desc = 'dict start'

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

	def getShort(self, pos):
		''' Returns a short unsigned integer at given position '''
		return parseInt(self.data[pos+4 : pos+4+2])

	def getDouble(self, pos):
		''' Returns a double at given position '''
		return parseDouble(self.data[pos+4 : pos+4+8])

	def getStr(self, pos, len=None):
		''' Returns string at given position
		@param len: if given, expects a fixed length string
		'''
		if len is None:
			return parseStr(self.data[pos+4:])
		else:
			return parseStr(self.data[pos+4:pos+4+len], fixed=True)

	def getByte(self, pos):
		''' Returns a single byte at given position '''
		return self.data[pos+4]

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
				ret += '  ' + row + os.linesep
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


class ExportsSection(Section):
	''' A section type 06: exported functions '''

	def __init__(self, data):
		super().__init__(1, data)
		self.func = collections.OrderedDict()
		for i in range(0, len(data), 41):
			f = ExportedFunction(data[i:i+41])
			self.func[f.start] = f
		self.log.debug('New exported functions section, functions: %s', self.func)

	def __str__(self):
		return str(self.func)

class ExportedFunction():
	''' A function inside an exported function section '''

	def __init__(self, data):
		self.name = parseStr(data[:33], True)
		self.args = parseInt(data[33:37])
		self.start = parseInt(data[37:])

	def __repr__(self):
		return '0x{:04X}: {}({}p)'.format(self.start, self.name, self.args)


class ParseError(Exception):
	pass

class SectionsError(ParseError):
	pass

class LogFormatter(logging.Formatter):
	''' Formats log into colored output for better readability '''

	COLORS = {
		'CRITICAL': (1, 91),
		'ERROR': (1, 31),
		'WARNING': (1, 33),
		'INFO': (0, 32),
		'DEBUG': (0, 34),
	}

	def __init__(self, fmt, color=True):
		super().__init__(fmt)
		self.color = color

	def format(self, record):
		msg = super().format(record)
		if self.color:
			msg = "\033[{};{}m".format(*self.COLORS[record.levelname]) + msg + "\033[0m"
		return msg


if __name__ == '__main__':
	import argparse
	import tempfile
	import subprocess

	parser = argparse.ArgumentParser()
	parser.add_argument('ecl_file', help='The compiled script')
	parser.add_argument('-d', '--dump', action='store_true', help='Dump disassembled program')
	parser.add_argument('-s', '--source', action='store_true', help='Dump disassembled source')
	parser.add_argument('-o', '--optimized', action='store_true', help='Dump optimized source')
	parser.add_argument('-v', '--verbose', action='store_true', help='Show debug output')
	parser.add_argument('-c', '--check', action='store_true', help='Check and compare the output')
	args = parser.parse_args()

	log = logging.getLogger()
	log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
	ch = logging.StreamHandler()
	fmt = LogFormatter("%(levelname)s:%(name)s:%(message)s")
	ch.setFormatter(fmt)
	log.addHandler(ch)

	ecl = ECLFile(args.ecl_file)

	if args.dump or args.check:
		if args.check:
			origf = tempfile.NamedTemporaryFile(prefix='DUMP_', suffix='_ORIG.txt', delete=False)
		for l in ecl.dump():
			if args.dump:
				print(l)
			if args.check:
				origf.write((l + os.linesep).encode('utf8'))
		if args.check:
			origf.close()

	if args.source or args.optimized or args.check:
		if args.check:
			decf = tempfile.NamedTemporaryFile(suffix='_dec.src', delete=False)
		src = []
		for l in ecl.source():
			if args.source:
				print(l)
			src.append(l)
		if args.optimized or args.check:
			for l in ecl.optimize(src):
				if args.optimized:
					print(l)
				if args.check:
					decf.write((l + os.linesep).encode('utf8'))
		if args.check:
			decf.close()

	if args.check:
		path = subprocess.check_output(('winepath', '-w', decf.name)).decode().strip()
		cmd = 'wine "' + os.path.join('scripts','ecompile.exe') + '" "' + path + '"'
		ret = subprocess.call(cmd, shell=True)
		os.unlink(decf.name)
		if ret:
			print('Compilation failed')
			sys.exit(1)

		newf = tempfile.NamedTemporaryFile(prefix='DUMP_', suffix='_DEC.txt', delete=False)
		e = decf.name[:-4] + '.ecl'
		eclc = ECLFile(e)
		for l in eclc.dump():
			newf.write((l + os.linesep).encode('utf8'))
		newf.close()
		os.unlink(e)

		cmd = ('kdiff3', origf.name, newf.name)
		subprocess.call(cmd)

		os.unlink(origf.name)
		os.unlink(newf.name)
