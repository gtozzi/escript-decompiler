#!/usr/bin/env python3

'''
Decompiles a whole POL project
'''

import os
import logging
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
	args = parser.parse_args()

	logging.basicConfig(level=logging.WARNING)

	start = datetime.datetime.now()
	bins = 0
	sizes = {} # Sizes of files with problems
	status = {} # Results
	for root, subdirs, files in os.walk(args.root):
		for f in files:
			if f.endswith('.ecl'):
				bins += 1
				binf = os.path.join(root,f)

				print(binf)

				sizes[binf] = os.stat(binf).st_size

				try:
					ecl = decompile.ECLFile(binf)
					src = ecl.optimize(list(ecl.source()))
				except Exception as e:
					status[binf] = 'decerr'
					print('ERROR: {}'.format(e))
					if args.halt:
						raise e
					else:
						continue

				out = tempfile.NamedTemporaryFile('wt', prefix='decompileall_', suffix='.src', delete=False)
				for line in src:
					out.write(line + '\n')
				out.close()

				path = subprocess.check_output(['winepath', '-w', out.name]).decode().strip()
				cmd = 'wine "' + os.path.join(args.root,'scripts','ecompile.exe') + '" "' + path + '"'
				ret = subprocess.call(cmd, shell=True)
				os.unlink(out.name)
				if ret:
					status[binf] = 'cmperr'
					continue

				cmpf = out.name[:-4] + '.ecl'
				if not filecmp.cmp(binf, cmpf):
					status[binf] = 'diff'
					continue

				status[binf] = 'ok'
				del sizes[binf]

	print('')
	s = list(status.values())
	decerr = s.count('decerr')
	cmperr = s.count('cmperr')
	diff = s.count('diff')
	ok = s.count('ok')
	f = (bins, decerr,decerr/bins, cmperr,cmperr/bins, diff,diff/bins, ok,ok/bins)
	print('Done. Took: {}'.format(datetime.datetime.now()-start))
	print('Found: {}, Decompile Errors: {} ({:.1%}), Compile Errors: {} ({:.1%}), Different: {} ({:.1%}), OK: {} ({:.1%})'.format(*f))
	print('Smallest files with problems:')
	siz = sorted(sizes, key=sizes.get)
	for i in range(1,6):
		print('{}. {}: {}'.format(i, siz[i], status[siz[i]].upper()))