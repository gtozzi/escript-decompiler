#!/usr/bin/env python3

'''
Decompiles a whole POL project
'''

import os
import logging
import tempfile
import subprocess
import filecmp

import decompile


if __name__ == '__main__':
	import argparse

	def check_folder(value):
		if not os.path.isdir(value):
			raise argparse.ArgumentTypeError('{} is not a valid folder'.format(value))
		return value

	parser = argparse.ArgumentParser()
	parser.add_argument('root', type=check_folder, help='The POL\'s root folder')
	args = parser.parse_args()

	logging.basicConfig(level=logging.WARNING)

	bins = 0
	decerr = 0
	cmperr = 0
	diff = 0
	ok = 0
	for root, subdirs, files in os.walk(args.root):
		for f in files:
			if f.endswith('.ecl'):
				bins += 1
				binf = os.path.join(root,f)

				print(binf)

				try:
					ecl = decompile.ECLFile(binf)
					src = ecl.optimize(list(ecl.source()))
				except Exception as e:
					decerr += 1
					print('ERROR: {}'.format(e))
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
					cmperr += 1
					continue

				cmpf = out.name[:-4] + '.ecl'
				if filecmp.cmp(binf, cmpf):
					diff += 1
					continue

				ok += 1

	print('')
	f = (bins, decerr,decerr/bins, cmperr,cmperr/bins, diff,diff/bins, ok,ok/bins)
	print('Done. Found: {}, Decompile Errors: {} ({:.1%}), Compile Errors: {} ({:.1%}), Different: {} ({:.1%}), OK: {} ({:.1%})'.format(*f))
