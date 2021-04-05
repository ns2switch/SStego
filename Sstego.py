"""SStego.py


Usage:
  SStego.py e -i <input> -o <output> -f <file> -p <password>
  SStego.py d -i <input> -o <output> -p <password>


Options:
  e                        Encode file
  d                        decode file
  -h, --help                Show this help
  --version                 Show the version
  -f,--file=<file>          File to hide
  -i,--in=<input>           Input image (carrier)
  -o,--out=<output>         Output image (or extracted file)
  -p,--password=<password>  Password to encrypt data

"""
import os
import sys
from dataclasses import dataclass
from docopt import docopt
from tools import *



# definimos los dataclass de cada archivo
@dataclass
class Img_info :
	name: str
	format: str
	size: int
	mode: str

	def max_size(self) :
		if self.mode in ['RGB', 'BGR', 'CMYK'] :
			return self.size[0] * self.size[1]  / 8
		elif self.mode == 'L' :
			return self.size[0] * self.size[1] / 8




def main() :
	args = docopt (__doc__, version='0.1')
	if args['e'] :
		# leemos argumento
		file_in = args['--in']
		file_out = args['--out']
		data_in = args['--file']
		secret = args['--password']
		try :
			size = os.path.getsize (file_in)
			print ("Size of " + str (file_in) + ': ' + str (size) + ' Bytes')
			in_image = read_image_info (file_in)
			infile = Img_info (file_in, in_image[0], in_image[1], in_image[2])
			print (' max file size to hide: %s bytes' % infile.max_size ())
			if infile.mode in ['1', '1;I', '1;R'] :
				sys.exit ('Cannot embed messages in black and white images')
			if infile.mode == 'P' :
				sys.exit ('Cannot embed messages in palette-mapped image')
			datas = read_file (data_in)
			sec = paswword_padding (secret)
			print ('encondig data')
			cdata = cifrado_cfb (sec, datas)
			print ('cypher data size: ', len (cdata) / 8)
			bytes_out = img_hide (file_in, cdata, file_out)
			print ("Process finished, your image is " + str (file_out) )
		except ValueError as e :
			print ('An Error Ocurred ', e)
			sys.exit

	elif args['d'] :
		# leemos argumentos
		file_in = args['--in']
		file_out = args['--out']
		secret = args['--password']
		try:
			print('Recovering data...')
			imagedata = recover_hide_data(file_in)
			cipher = recover_bit_data(imagedata)
			password = paswword_padding(secret)
			outdata = descifrado_cfb(password,cipher[0],cipher[1])
			save_file(file_out,outdata)
			print('Data recovered in',file_out)
		except ValueError as e:
			print ('An Error Ocurred ', e)
			sys.exit



if __name__ == '__main__' :
	main ()
