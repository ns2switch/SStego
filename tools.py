import secrets
from PIL import Image, ImageStat
from bitstring import BitArray
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_KEYLEN = 16
KEY_LENGTHS = (16, 24, 32)
OFFSET = 40


def read_image_info(file) :  # Leemos la imagen de entrada y comprobamos el tipo y el tamaño
	im = Image.open (file, 'r')
	stat = ImageStat.Stat (im)
	print ('Average (arithmetic mean) pixel level for each band: ',stat.mean)
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
	data_len = len(string)
	databit = BitArray (uint=(data_len + 1),length=31).bin
	databit_len = len(databit)
	index = 0
	indexdata = 0

	for x in range (OFFSET-8, OFFSET) :
		for y in range (OFFSET-8, OFFSET) :
			pixel = image.getpixel ((x, y))
			if index < databit_len :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				pixelbitR = pixelbitR[:-1] + databit[index]
				index += 1
			if index >= databit_len :
				break
			image.putpixel ((x, y), (BitArray (bin=pixelbitR).uint, pixel[1], pixel[2]))

	for x in range (OFFSET+1, width) :
		for y in range (OFFSET+1, height) :
			pixel = image.getpixel ((x, y))
			if indexdata < data_len :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				pixelbitR = pixelbitR[:-1] + string[indexdata]
				indexdata += 1
			if indexdata >= data_len :
				break
			image.putpixel ((x, y),(BitArray(bin=pixelbitR).uint, pixel[1],pixel[2]))
	stat = ImageStat.Stat (image)
	print ('Average (arithmetic mean) pixel level for each band: ',stat.mean)
	image.save (file_out)


def recover_hide_data(img) :
	image = Image.open(img)
	width, height = image.size
	index = 0
	indexdata = 0
	bufArray = ''
	lenArray = ''
	for x in range (OFFSET-8, OFFSET) :
		for y in range (OFFSET-8, OFFSET) :
			pixel = image.getpixel ((x, y))
			if index < 32 :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				data = pixelbitR[-1:]
				index += 1
			if index >= 32:
				break
			lenArray +=str (data)
	len = BitArray(bin=lenArray).uint
	data_len = len+1
	for x in range (OFFSET+1, width) :
		for y in range (OFFSET+1, height) :
			pixel = image.getpixel ((x, y))
			if indexdata < data_len :
				pixelbitR = BitArray (uint=pixel[0], length=8).bin
				bufArrayR = pixelbitR[-1:]
				indexdata += 1
			if indexdata >= data_len :
				break
			bufArray +=str(bufArrayR)
	return bufArray


def recover_bit_data(data) :
	bytes = int (data, 2).to_bytes ((len (data) + 7) // 8, byteorder='big')
	iv = bytes[-16:]
	data = bytes[:-16]
	return [iv, data]


def descifrado_cfb(secreto, iv, datas) :
	cipher = Cipher (algorithms.AES (secreto), modes.CFB (iv))
	decryptor = cipher.decryptor ()
	value = decryptor.update (datas) + decryptor.finalize ()
	return value

def save_file(file_out,data):
	with open(file_out, 'wb') as output:
		output.write(data)