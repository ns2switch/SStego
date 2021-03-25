#!/usr/bin/env python3
# coding:UTF-8

"""SStego.py

Usage:
  SStego.py encode -i <input> -o <output> -f <file> -p password
  SStego.py decode -i <input> -o <output> -p password

Options:
  -h, --help                Show this help
  --version                 Show the version
  -f,--file=<file>          File to hide
  -i,--in=<input>           Input image (carrier)
  -o,--out=<output>         Output image (or extracted file)

"""
from docopt import docopt

def main() :
	args = docopt(__doc__, version='Naval Fate 2.0')
	in_f = args["--in"]
	out_f = args["--out"]


	if args['encode'] :
		print ("encode")


	elif args["decode"] :
		print("decode")


if __name__ == '__main__' :
	main ()
