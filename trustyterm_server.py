from IPy import IP
from Crypto.Hash import SHA512
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_PKCS1_v1_5	# for verifying signature of the Authorized IP addresses list
from Crypto.Signature import pss	# for digitally signing Shared Secret
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5	# for encrypting shared secret
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64, binascii, json, ast
import secrets, hashlib, random
import signal, time, sys, os, re
import posix_ipc
import requests
import _thread
import threading, RLock

from Crypto import Random
import hashlib

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import ssl
import urllib.parse
from urllib.parse import urlparse, parse_qs

from datetime import datetime

#Disable warning because we don't want to verify the certificate in https requests
requests.packages.urllib3.disable_warnings()

HTTP_SERVICE_UNAVAILABLE_CODE = 503

SESSION_SETUP_SEM_NAME = "/session_setup_semaphore"
SESSION_SETUP_SEM_PATH = "/dev/shm/sem.session_setup_semaphore"
SESSION_SETUP_FIFO_PATH = "/tmp/session_setup_fifo"
CMD_RUN_SSHD = "/usr/local/sbin/sshd"

pk_ts_dict = {} # Keys are SSH_SIDs, Values are TT_SIDs
mutex = RLock()	# For protecting pk_ts_dict from race conditions

auth_timeout = 0	# Will be substituted by the value in /etc/ssh/sshd_config 'LoginGraceTime' value

def ssh_auth_read_timeout():
	# Reading LoginGraceTime from /etc/ssh/sshd_config, and saving the value to the timeout variable (in seconds)
	global auth_timeout

	f = open("/etc/ssh/sshd_config", "r")
	for row in f:
		if("LoginGraceTime" in row):
			s = row.strip().split(" ")
			if(s[1].endswith('s')):
				auth_timeout = s[1][:-1]
			elif(s[1].endswith('m')):
				auth_timeout = str(int(s[1][:-1])*60)
			else:
				print("Error: LoginGraceTime not well formatted!")
				exit()

def sessions_fifos_cleanup():
	# Unlinking all the ssh2tt and tt2ssh FIFOs
	try:
		for f in os.listdir('/tmp/'):
			if re.search('ssh2tt_*', f):
				os.unlink(os.path.join('/tmp/', f))
				#os.remove(os.path.join('/tmp/', f))
		for f in os.listdir('/tmp/'):
			if re.search('tt2ssh_*', f):
				os.unlink(os.path.join('/tmp/', f))
				#os.remove(os.path.join('/tmp/', f))
	except:
		pass
	
def sigint_handler(signum, frame):
	# Unlinking pending session fifos
	sessions_fifos_cleanup()
	quit("\n")

# Class that receives HTTP GET Requests
class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
	
	# Method that responds to HTTP GET Requests
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
		
		ip_addr = self.client_address[0] # IP Addr of the host which made this request
		
		query_components = parse_qs(urlparse(self.path).query) # dictionary containing HTTP Request parameters
		keys = query_components.keys()

		if('TT_SID' in keys and 'IV' in keys and 'EncJSON' in keys and 'EncKey' in keys and 'JSONsig' in keys):
			try:
				tt_sid = query_components['TT_SID'][0]
				#ssh_sid = query_components['SSH_SID'][0]			
				iv_hex = query_components['IV'][0]
				encJSON_hex = query_components['EncJSON'][0]	# Hex of JSON of SSH-SIG and PubKey encrypted with AES-CBC
				encAesKey_hex = query_components['EncKey'][0]	# Hex of Aes Key wncrypted with AES-CBC
				JSONsig_hex = query_components['JSONsig'][0]	# Hex of signature of above encrypted JSON


				# Decrypting AES key to decrypt JSON of SSH-SIG and PubKey
				rsa_privkey = RSA.importKey(open('/etc/ssh/ssh_host_rsa_key').read())	# Loading Server Host RSA Private Key
				cipher = PKCS1_OAEP.new(rsa_privkey, hashAlgo=SHA256)	# building Cipher Object for decrypting AES Key with RSA-OAEP

				encAesKey_bytes = bytes.fromhex(encAesKey_hex) # ByteArray of the Hex of the encrypted AES Key
				decAesKey_bytes = cipher.decrypt(encAesKey_bytes) # ByteArray of Decrypted AES Key

				# Decrypting JSON of SSH-SIG and PubKey
				iv_bytes = bytes.fromhex(iv_hex)
				encJSON_bytes = bytes.fromhex(encJSON_hex)
				aes = AES.new(decAesKey_bytes, AES.MODE_CBC, iv_bytes)
				decJSON_bytes = aes.decrypt(encJSON_bytes)
				decJSON = decJSON_bytes.decode("utf-8")
				decJSON = decJSON[:-ord(decJSON[-1])]
				
				# Now that I have the JSON in plaintext, I have to verify its signature, and if it is correct
				# I can save the PubKey received in the dictionary to match it with a TrustyTerm session and finally
				# I can send the decrypted SSH-SIG to Proxy to let it conclude SSH-AUTH
				
				json_obj = json.loads(decJSON)
				pubkey = json_obj["pubkey"] # Public Key contained in the JSON, sent by the Browser
				pubk = RSA.importKey(pubkey) # Public Key object to be used for signature verification
				
				JSONsig_bytes = bytes.fromhex(JSONsig_hex) #BytesArray of the signature of the JSON computed by the browser and sent as HTTP param
				
				h = SHA256.new(decJSON.encode()) # I have to use the unpadded plaintext here
				verifier = pss.new(pubk,salt_bytes=32) # RSA-PSS verifier object
				
				verifier.verify(h,JSONsig_bytes) # If it fails, it should throw an exception
				
				# If I am here, the verification succeeded (otherwise an exception would have been thrown

				# Sending to Proxy the Decrypted Signature
				requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': tt_sid, 'DecrSig': json_obj["ssh-sig"]}, verify = False)
				
				# Saving in the global dict the match between PubKey and TimeStamp
				global pk_ts_dict
				global mutex
				
				mutex.acquire()
				pk_ts_dict[pubkey] = (datetime.now(),tt_sid)
				mutex.release()
				
				return
				

			except Exception as e:
				print(e)
				# Telling Proxy that something went wrong
				requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': "", 'DecrSig': 'InvalidParams'}, verify = False)
					
				return
		else:
			print("[HTTPS Handler] Invalid HTTP params")
			requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': "", 'DecrSig': 'InvalidParams'}, verify = False)
			
			return


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def https_manager(x,y):
	# print('[*] HTTP Handler Thread: Avvio del server...')
	server_address = ('0.0.0.0', 443) # Listen on any IP Addr on port 443, i.e. HTTPS connection
	httpd = ThreadedHTTPServer(server_address, testHTTPServer_RequestHandler)
	httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./cert.pem', server_side=True)
	httpd.serve_forever()


def tt_fifo_read(sshd_session):
	ssh2tt_fifo = open(sshd_session['ssh2tt_fifo_name'], 'r')
	sshd_data = ssh2tt_fifo.read()
	ssh2tt_fifo.close()
	return sshd_data


def tt_fifo_write(data, sshd_session):
	tt2ssh_fifo = open(sshd_session['tt2ssh_fifo_name'], 'w')
	tt2ssh_fifo.write(data)
	tt2ssh_fifo.close()


def session_management(threadName, sshd_session):
	
	# If I am here, I'm handling a TrustyTerm Session (check has been already done by main Thread)
	# I have to send to Proxy the Shared Secret and its Digital Signature, in the meanwhile Browser is polling for them
	
	# Getting public key object to encrypt session parameters to send
	rsa = RSA.importKey(sshd_session['public_key']) # Public Key of the Client (Browser)
	cipher = Cipher_PKCS1_v1_5.new(rsa)

	# Session setup data (JSON formatted) encryption using user public key
	rsa_decrypted_data = "{\"tt_aes_key\": \"" + sshd_session['tt_aes_key'] +"\"}"
	rsa_decrypted_data_encode = rsa_decrypted_data.encode() #encoded UTF-8 JSON Shared Secret
	rsa_encrypted_data = cipher.encrypt(rsa_decrypted_data_encode) # encryption of the UTF-8 encoded JSON Shared Secret
	cipher_b64 = base64.b64encode(rsa_encrypted_data).decode()	# base64 string of encrypted Shared Secret
	#print("Base64 of encrypted Shared Secret: " + cipher_b64);

	# Signing Shared Secret with Server Private Key (PKCS#1 formatted Private Key)
	#rsa_privkey = RSA.importKey(open('/home/'+sshd_session['username']+'/.ssh/id_rsa.pkcs1.priv').read())
	rsa_privkey = RSA.importKey(open('/etc/ssh/ssh_host_rsa_key').read())
	h = SHA256.new(rsa_decrypted_data_encode) # bytes of the hash of the Shared Secret
	#signer = Signature_PKCS1_v1_5.new(rsa_privkey)
	signer = pss.new(rsa_privkey,salt_bytes=32)
	signature_bytes = signer.sign(h) # bytes of the signature of the Shared Secret
	signature_b64 = base64.b64encode(signature_bytes).decode()
	#print("Base64 of signature of Shared Secret: " + signature_b64)

	try:
		#Send (base64 encoded) encrypted session setup data to proxy (session setup phase 2)
		proxy_res = requests.get(url = "https://" + sshd_session['remote_ipaddr'] + "/trustyterm/server_session_setup", params = {'phase': 2, 'tt_session_id': sshd_session['tt_session_id'], 'encrypted_data': cipher_b64, 'signat': signature_b64}, verify = False)
	except requests.exceptions.RequestException as e:
		print("[*] Connection error: %s" % e)
		_thread.exit()

	while True:
		# I am blocked here reading from SSHD fifo, whenever I read something it means SSHD sent "AUTH_FAILED", meaning SSHD failed AES-GCM, so keystrokes could be compromised
		sshd_resp = tt_fifo_read(sshd_session)
		if(sshd_resp=="AUTH_FAILED"):
			print("SSHD AES-GCM auth fail for session " + sshd_session['tt_session_id'] + ". Notifying Proxy...")
			try:
				#Auth fail notification
				proxy_res = requests.get(url = "https://" + sshd_session[remote_ipaddr] + "/trustyterm/notify_auth_fail", params = {'TT_SID': sshd_session['tt_session_id']}, verify = False)
			except requests.excpetions.RequestException as e:
				print("Notifying Proxy failed for session " + sshd_session['tt_session_id'] + ". Connection error: %s" %e)
				_thread.exit()
		else:
			print("SSH Connection " + sshd_session['ssh_session_id'] + " closed. Unlinking session FIFOs and killing thread...\n")
			os.unlink(sshd_session['ssh2tt_fifo_name'])
			os.unlink(sshd_session['tt2ssh_fifo_name'])
			_thread.exit()

def main():
	
	print(threading.currentThread().name)
	
	signal.signal(signal.SIGINT, sigint_handler)
	
	# Unlinking pending session fifos
	sessions_fifos_cleanup()
	
	ssh_auth_read_timeout()
	
	global auth_timeout
	print("TrustyTerm AUTH timeout set to " + str(auth_timeout) + " secs")

	#Starting thread for HTTP requests management
	try:
		print("[*] Creation of a new thread for HTTPS requests management")
		_thread.start_new_thread(https_manager, (None,None))
		print("[*] Thread for HTTP requests management started\n")
	except OSError as e:
		print ("[*] Unable to start the Thread for HTTPS requests management: %s" % e)
		sys.exit(1)

	#Check if the session setup FIFO already exists and if not create it
	try:
		os.mkfifo(SESSION_SETUP_FIFO_PATH)
		os.chmod(SESSION_SETUP_FIFO_PATH, 0o666)
	except OSError:
		try:
			os.unlink(SESSION_SETUP_FIFO_PATH)
			os.mkfifo(SESSION_SETUP_FIFO_PATH)
			os.chmod(SESSION_SETUP_FIFO_PATH, 0o666)
		except OSError as e:
			print("[*] Session setup FIFO error: %s" % e)
			sys.exit(1)

	#Open named semaphore used during session setup
	session_setup_sem = None
	try:
		session_setup_sem = posix_ipc.Semaphore(SESSION_SETUP_SEM_NAME, posix_ipc.O_CREX, initial_value = 1)
		os.chmod(SESSION_SETUP_SEM_PATH, 0o666)
	except posix_ipc.ExistentialError:
		#Destroy the old semaphore
		session_setup_sem = posix_ipc.Semaphore(SESSION_SETUP_SEM_NAME, 0)
		session_setup_sem.unlink()
		#Create a new semaphore
		session_setup_sem = posix_ipc.Semaphore(SESSION_SETUP_SEM_NAME, posix_ipc.O_CREX, initial_value = 1)
		os.chmod(SESSION_SETUP_SEM_PATH, 0o666)

	#Start the sshd deamon
	os.system(CMD_RUN_SSHD)
	print("[*] sshd deamon started")
	print("[*] Listening for new SSH sessions\n")

	#Listening on session setup FIFO
	while True:
		#Initalize dict with all necessary ssh session data
		sshd_session = {'ssh_session_id':""}

		with open(SESSION_SETUP_FIFO_PATH, 'r') as session_setup:
			#Open and read data from session setup fifo
			try:
				dati_letti = session_setup.read()
				print(dati_letti)
				session_setup_data = json.loads(dati_letti)
			except OSError as e:
				print("[*] Error occured while parsing session setup data from sshd: %s" % e)
				session_setup_sem.release()
				continue

			#Save all session setup data received from sshd
			sshd_session['ssh_session_id'] = session_setup_data['ssh_session_id']
			sshd_session['ssh2tt_fifo_name'] = "/tmp/ssh2tt_" + sshd_session['ssh_session_id']
			sshd_session['tt2ssh_fifo_name'] = "/tmp/tt2ssh_" + sshd_session['ssh_session_id']
			sshd_session['remote_ipaddr'] = session_setup_data['remote_ipaddr']
			sshd_session['public_key'] = session_setup_data['public_key']
			sshd_session['username'] = session_setup_data['username']
			sshd_session['tt_aes_key'] = session_setup_data['tt_aes_key']   # 256 bit AES key produced by SSHD, to be sent to Browser as 'Shared Secret'
			
			#print(sshd_session)

			#Once we've read from session_setup_fifo we can release the semaphore
			session_setup_sem.release()
			session_setup.close()
			

			# Here I have to check if this is a Trustyerm Session
			global pk_ts_dict
			global mutex
			pubkey = sshd_session['public_key']
			if(pubkey in pk_ts_dict):
				# Dictionary has the PubKey, this could be a TrustyTerm session. I have to check the TimeStamp
				currtime = datetime.now()
				datetimeDifference = currtime - pk_ts_dict[pubkey][0] # Difference between the current time and the TimeStamp saved into the dictionary
				diff_secs = datetimeDifference.total_seconds()
				if(diff_secs < int(auth_timeout)):
					# This means that the Proxy succesfully made SSH-AUTH in time, this is a TrustyTerm session
					sshd_session['tt_session_id'] = pk_ts_dict[pubkey][1]
					mutex.acquire()
					del pk_ts_dict[pubkey]	# Once I know the nature of this session, I can just remove it from global dict
					mutex.release()
					tt_fifo_write("TT", sshd_session)
					
					#Starting thread for the management of the new session
					try:
						print("[*] Creation of a new thread for current session management")
						_thread.start_new_thread(session_management, ("Thread-"+sshd_session['ssh_session_id'], sshd_session,))
						print("[*] New session started from <" + sshd_session['remote_ipaddr'] + ">\n")
					except OSError as e:
						print ("[*] Unable to start a new thread: %s" % e)
					
				else:
					# This means that the information in the dictionary is an old information, this is not a TrustyTerm session
					mutex.acquire()
					del pk_ts_dict[pubkey]
					mutex.release()
					tt_fifo_write("NTT", sshd_session)
			else:
				# Public Key never appeared in the dictionary, this is not a TrustyTerm session for sure
				tt_fifo_write("NTT", sshd_session)


if __name__ == '__main__':
    main()
