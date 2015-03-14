#!/usr/bin/env python3

'''
Decompiles a whole POL project
'''

import os, sys
import logging
import collections
import tempfile
import subprocess
import filecmp
import datetime

import decompile


if __name__ == '__main__':
	import argparse

	def check_folder(value):
		if not os.path.isdir(value):
			raise argparse.ArgumentTypeError('{} is not a valid folder'.format(value))
		return value

	parser = argparse.ArgumentParser()
	parser.add_argument('root', type=check_folder, help='The POL\'s root folder')
	parser.add_argument('-a', '--halt', action='store_true', help='Halt on error')
	parser.add_argument('-s', '--skip', type=int, default=0, help='Skip first number of files')
	args = parser.parse_args()

	logging.basicConfig(level=logging.WARNING)

	start = datetime.datetime.now()

	# First scan all binaries and get their size
	sizes = collections.OrderedDict()
	for root, subdirs, files in os.walk(args.root):
		for f in files:
			if f.endswith('.ecl'):
				binf = os.path.join(root,f)
				sizes[binf] = os.stat(binf).st_size

	# Then proceed by size, from smaller to bigger (useful for debugging with -a flag)
	status = {}
	i = 0
	for binf in sorted(sizes, key=sizes.get):
		i += 1
		print('{}/{}: {}'.format(i, len(sizes), binf))
		if i <= args.skip:
			print('skipping...')
			continue

		try:
			ecl = decompile.ECLFile(binf)
			src = ecl.optimize(list(ecl.source()))
		except Exception as e:
			if args.halt:
				print('DECOMPILE ERROR: {}'.format(e))
				sys.exit(1)
			else:
				status[binf] = 'decerr'
				continue

		out = tempfile.NamedTemporaryFile('wb', prefix='decompileall_', suffix='.src', delete=False)
		for line in src:
			out.write((line + os.linesep).encode('utf8'))
		out.close()

		path = subprocess.check_output(['winepath', '-w', out.name]).decode().strip()
		cmd = 'wine "' + os.path.join(args.root,'scripts','ecompile.exe') + '" "' + path + '"'
		ret = subprocess.call(cmd, shell=True)
		os.unlink(out.name)
		if ret:
			if args.halt:
				print('COMPILE ERROR {}'.format(ret))
				sys.exit(1)
			else:
				status[binf] = 'cmperr'
				continue

		cmpf = out.name[:-4] + '.ecl'
		if not filecmp.cmp(binf, cmpf):
			if args.halt:
				print('DIFF ERROR')
				sys.exit(1)
			else:
				status[binf] = 'diff'
				continue

		status[binf] = 'ok'


	print('')
	s = list(status.values())
	decerr = s.count('decerr')
	cmperr = s.count('cmperr')
	diff = s.count('diff')
	ok = s.count('ok')
	bins = len(status)
	f = (bins, decerr,decerr/bins, cmperr,cmperr/bins, diff,diff/bins, ok,ok/bins)
	print('Done. Took: {}'.format(datetime.datetime.now()-start))
	print('Found: {}, Decompile Errors: {} ({:.1%}), Compile Errors: {} ({:.1%}), Different: {} ({:.1%}), OK: {} ({:.1%})'.format(*f))
