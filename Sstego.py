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
  -p,--password=<password>  Password to encrypt data Minimo 16 caracteres

"""
import os
import secrets
import sys
from dataclasses import dataclass

from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from docopt import docopt


# definimos los dataclass de cada archivo
@dataclass
class Img_info :
	name: str
	format: str
	size: int
	mode: str

	def max_size(self) :
		if self.mode in ['RGB', 'BGR', 'CMYK'] :
			print ('Color image')
			return self.size[0] * self.size[1] * 8 * 3
		elif self.mode == 'L' :
			print ('Grey Scale Image')
			return self.size[0] * self.size[1] * 8


def read_image_info(file) :  # Leemos la imagen de entrada y comprobamos el tipo y el tamaño
	im = Image.open (file, 'r')
	im.close ()
	return im.format, im.size, im.mode

def convert_to_bit_array(img):
	im = Image.open(img,'r')


def read_file(file) :  # funcion de lectura de archivos
	archivo = open (file,'rb')
	value = archivo.read ()
	archivo.close ()
	return value


def write_file(file, data) :  # Funcion para la escritura de archivos en modo binario
	archivo = open (file, 'wb')
	value = archivo.write (data)
	archivo.close ()


def cifradocfb(secreto, datas) :
	iv = secrets.token_bytes (16)
	cipher = Cipher (algorithms.AES (secreto), modes.CFB (iv))  # Elegimos el algoritmo de cifrado y el modo
	encryptor = cipher.encryptor ()  # Iniciamos el cifrado
	ct = encryptor.update (datas) + encryptor.finalize ()  # Creamos el texto cifrado
	value = ''.join(format(byte, '08b') for byte in ct)
	return value



def descifradocfb(secreto, iv, datas) :
	cipher = Cipher (algorithms.AES (secreto), modes.CFB (iv))  # Elegimos el algoritmo de cifrado
	decryptor = cipher.decryptor ()  # Desciframos el criptograma
	text = decryptor.update (datas) + decryptor.finalize ()  # finalizamos el descifrado
	return text


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
			print ("Size (In bytes) of '%s':" % file_in, size)
			in_image = read_image_info (file_in)
			infile = Img_info (file_in, in_image[0], in_image[1], in_image[2])
			if infile.mode in ['1', '1;I', '1;R'] :
				sys.exit ('Cannot embed messages in black and white images')
			if infile.mode == 'P' :
				sys.exit ('Cannot embed messages in palette-mapped image')
			datas = read_file(data_in)
			sec = bytes (secret, encoding='utf8')
			cdata = cifradocfb(sec,datas)
			print ('Tamaño de los datos cifrados: ' ,len (cdata))
			print (' max file size to hide: %s bytes' % infile.max_size ())

		except ValueError as e:
			print  ('An Error Ocurred ', e)
			sys.exit

	elif args['d'] :
		# leemos argumentos
		file_in = args['--in']
		file_out = args['--out']
		data_in = args['--file']
		secret = args['--password']
		print ('decode')


if __name__ == '__main__' :
	main ()
