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
import io
import mmap
import os
import secrets
import sys
import itertools
from dataclasses import dataclass

import bitstring
import numpy as np
from PIL import Image, ImageStat
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from docopt import docopt
from bitstring import BitArray

DEFAULT_KEYLEN = 16
KEY_LENGTHS = (16, 24, 32)
OFFSET = 16


# definimos los dataclass de cada archivo
@dataclass
class Img_info :
	name: str
	format: str
	size: int
	mode: str

	def max_size(self) :
		if self.mode in ['RGB', 'BGR', 'CMYK'] :
			return self.size[0] * self.size[1] * 2 / 8
		elif self.mode == 'L' :
			return self.size[0] * self.size[1] / 8


def read_image_info(file) :  # Leemos la imagen de entrada y comprobamos el tipo y el tamaño
	im = Image.open (file, 'r')
	stat = ImageStat.Stat (im)
	print (stat.mean)
	im.close ()
	return im.format, im.size, im.mode


def read_file(file) :  # funcion de lectura de archivos
	archivo = open (file, 'rb')
	value = archivo.read ()
	archivo.close ()
	return value


def paswword_padding(passwd) :
	passlen = len (passwd)
	passbyte = bytes (passwd, 'UTF-8')
	if passlen not in KEY_LENGTHS :
		if passlen < 16 :
			padder = padding.ANSIX923 (128).padder ()
			pad_passwd = padder.update (passbyte)
			pad_passwd += padder.finalize ()
		elif passlen < 24 :
			padder = padding.ANSIX923 (192).padder ()
			pad_passwd = padder.update (passbyte)
			pad_passwd += padder.finalize ()
		elif passlen < 32 :
			padder = padding.ANSIX923 (256).padder ()
			pad_passwd = padder.update (passbyte)
			pad_passwd += padder.finalize ()
		else :
			print ('Password cant be larger than 32bytes')
	return pad_passwd


def cifrado_cfb(secreto, datas) :
	iv = secrets.token_bytes (16)
	cipher = Cipher (algorithms.AES (secreto), modes.CFB (iv))  # Elegimos el algoritmo de cifrado y el modo
	encryptor = cipher.encryptor ()  # Iniciamos el cifrado
	ct = encryptor.update (datas) + encryptor.finalize ()  # Creamos el texto cifrado
	ctadd = b''.join ([ct, iv])
	value = ''.join (format (byte, '08b') for byte in ctadd)
	return value

#Es mas rapido hacerlo con putdata , se necesita cambiar.
def img_hide(img, string, file_out) :
	image = Image.open (img, 'r')
	width, height = image.size
	data_len = len (string)
	index = 0
	for x in range (OFFSET, width) :
		for y in range (OFFSET, height) :
			pixel = image.getpixel ((x, y))
			if index < data_len :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				pixelbitR = pixelbitR[:-1] + string[index]
				index += 1

			if index >= data_len :
				break

			image.putpixel ((x, y),(BitArray(bin=pixelbitR).uint, pixel[1],pixel[2]))
	stat = ImageStat.Stat (image)
	print (stat.mean)
	image.save (file_out)
	with open(file_out,"a") as file:
		file.write("#N"+str(data_len))

def get_n_least_significant_bits(value, n):
    value = value << 255 - n
    value = value % 255
    return value >> 8 - n


def recover_hide_data(img, size) :
	image = Image.open(img)
	width, height = image.size
	index = 0
	bufArray = ''
	data_len = size
	for x in range (OFFSET, width) :
		for y in range (OFFSET, height) :
			pixel = image.getpixel ((x, y))
			if index < data_len :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				bufArrayR = pixelbitR[-1:]
				index += 1

			if index >= data_len :
				break
			bufArray +=str(bufArrayR)
	print(bufArray)
	return bufArray


def recover_bit_data(data) :
	bytes = int (data, 2).to_bytes ((len (data) + 7) // 8, byteorder='big')
	iv = bytes[-16 :]
	data = bytes[:-16]
	print(data)
	return [iv, data]


def descifrado_cfb(secreto, iv, datas) :
	cipher = Cipher (algorithms.AES (secreto), modes.CFB (iv))
	decryptor = cipher.decryptor ()
	value = decryptor.update (datas) + decryptor.finalize ()
	print(value)
	return value

def save_file(file_out,data):
	with open(file_out, 'wb') as output:
		output.write(data)

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
			print(cdata)
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
			imagedata = recover_hide_data(file_in,161)
			cipher = recover_bit_data(imagedata)
			password = paswword_padding(secret)
			outdata = descifrado_cfb(password,cipher[0],cipher[1])
			save_file(file_out,outdata)
		except ValueError as e:
			print ('An Error Ocurred ', e)
			sys.exit



if __name__ == '__main__' :
	main ()
