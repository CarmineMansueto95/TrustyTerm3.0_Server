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

from Crypto import Random
import hashlib

from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import urllib.parse
from urllib.parse import urlparse, parse_qs

#Disable warning because we don't want to verify the certificate in https requests
requests.packages.urllib3.disable_warnings()

HTTP_SERVICE_UNAVAILABLE_CODE = 503

SESSION_SETUP_SEM_NAME = "/session_setup_semaphore"
SESSION_SETUP_SEM_PATH = "/dev/shm/sem.session_setup_semaphore"
SESSION_SETUP_FIFO_PATH = "/tmp/session_setup_fifo"
CMD_RUN_SSHD = "/usr/local/sbin/sshd"

ssh_tt_sids = {} # Keys are SSH_SIDs, Values are TT_SIDs
handling_session = 0 # Like a sempahore, if a TrustyTerm Session is being set up, other ones have to wait (and also because multiple HTTP requests would fill ssh_tt_sid dictionary)

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
		
		global handling_session
		handling_session +=1

		# If I am already handling a session, I do not handle this Session, i.e. I do not fill dictionary and I do not send to Proxy the Decrypted Signature
		if(handling_session > 1):

			# Response
			self.wfile.write(bytes("", "utf8"))
			return
		
		ip_addr = self.client_address[0] # IP Addr of the host which made this request
		
		query_components = parse_qs(urlparse(self.path).query) # dictionary containing HTTP Request parameters
		keys = query_components.keys()

		if('TT_SID' in keys and 'SSH_SID' in keys and 'IV' in keys and 'EncSig' in keys and 'EncKey' in keys):
			if(query_components['TT_SID'][0] != "" and query_components['SSH_SID'][0] != ""):
				tt_sid = query_components['TT_SID'][0]
				ssh_sid = query_components['SSH_SID'][0]			
				iv_hex = query_components['IV'][0]
				encSig_hex = query_components['EncSig'][0]	# Hex of Digital Signature encrypted with AES-CBC
				encAesKey_hex = query_components['EncKey'][0]	# Hex of Aes Key wncrypted with AES-CBC
				# print("[HTTP Handler Thread]\n\tSSH_SID: " + ssh_sid + "\n\tTT_SID: " + tt_sid)

				rsa_privkey = RSA.importKey(open('/etc/ssh/ssh_host_rsa_key').read())	# Loading Server Host RSA Private Key
				cipher = PKCS1_OAEP.new(rsa_privkey, hashAlgo=SHA256)	# building Cipher Object for decrypting Aes Key with RSA-OAEP

				encAesKey_bytes = bytes.fromhex(encAesKey_hex) # ByteArray of the Hex of the encrypted AES Key
				decAesKey_bytes = cipher.decrypt(encAesKey_bytes) # ByteArray of Decrypted AES Key

				# Decrypting Digital Signature
				iv_bytes = bytes.fromhex(iv_hex)
				encSig_bytes = bytes.fromhex(encSig_hex)
				aes = AES.new(decAesKey_bytes, AES.MODE_CBC, iv_bytes)
				decSig_bytes = aes.decrypt(encSig_bytes)
				decSig_hex = decSig_bytes.hex()
				# print("Decrypted Digital Signature: " + decSig_hex)

				# Creating matching between SSH_SID and TT_SID in global dict
				global ssh_tt_sids
				ssh_tt_sids[ssh_sid] = tt_sid

				# Sending to Proxy the Decrypted Signature
				try:
					requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': tt_sid, 'DecrSig': decSig_hex}, verify = False)
				
					# Response
					self.wfile.write(bytes("", "utf8"))
					return
				except:
					print("[HTTPS Handler] Failed to send Decrypted Signature to " + ip_addr)
					del ssh_tt_sids[ssh_sid] # Removing SSH_SID-TT_SID matching in global dictionary
					handling_session-=1 # I'm no longer handling this session since I could not send Decrypted Signature to the Proxy

			else:
				print("[HTTPS Handler] TT_SID or SSH_SID are empty!")
				
				try:
					requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': "", 'DecrSig': 'InvalidParams'}, verify = False)
					# Response
					self.wfile.write(bytes("", "utf8"))
					return
				except:
					print("[HTTPS Handler] Failed to send 'Invalid Params' response to " + ip_addr)

		else:
			print("[HTTPS Handler] Missing some HTTP Param!")
			try:
				requests.get(url = "https://" + ip_addr + "/trustyterm/decr_sig", params = {'TT_SID': "", 'DecrSig': 'InvalidParams'}, verify = False)

				# Response
				self.wfile.write(bytes("", "utf8"))
				return
			except:
				print("[HTTPS Handler] Failed to send 'Invalid Params' response to " + ip_addr)

def https_manager(x,y):
	# print('[*] HTTP Handler Thread: Avvio del server...')
	server_address = ('0.0.0.0', 443) # Listen on any IP Addr on port 443, i.e. HTTPS connection
	httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
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
	#rsa_decrypted_data = "{\"session_token\": \"" + sshd_session['session_token'] + "\", \"counter\": \"" + str(sshd_session['initial_counter']) + "\", \"tt_aes_key\": \"" + sshd_session['tt_aes_key'] +"\"}"
	rsa_decrypted_data = "{\"tt_aes_key\": \"" + sshd_session['tt_aes_key'] +"\"}"
	rsa_decrypted_data_encode = rsa_decrypted_data.encode() #encoded UTF-8  JSON Shared Secret
	rsa_encrypted_data = cipher.encrypt(rsa_decrypted_data_encode) # encryption of the UTF-8 encoded JSON Shared Secret
	cipher_b64 = base64.b64encode(rsa_encrypted_data).decode()	# base64 string of encrypted Shared Secret
	#print("Base64 of encrypted Shared Secret: " + cipher_b64);

	# Signing Shared Secret with Server Private Key (PKCS#1 formatted Private Key)
	#rsa_privkey = RSA.importKey(open('/home/'+sshd_session['username']+'/.ssh/id_rsa.pkcs1.priv').read())
	rsa_privkey = RSA.importKey(open('/etc/ssh/ssh_host_rsa_key').read())
	h = SHA512.new(rsa_decrypted_data_encode) # bytes of the hash of the Shared Secret
	#signer = Signature_PKCS1_v1_5.new(rsa_privkey)
	signer = pss.new(rsa_privkey,salt_bytes=32)
	signature_bytes = signer.sign(h) # bytes of the signature of the Shared Secret
	signature_b64 = base64.b64encode(signature_bytes).decode()
	#print("Base64 of signature of Shared Secret: " + signature_b64)

	try:
		#Send (base64 encoded) encrypted session setup data to proxy (session setup phase 2)
		proxy_res = requests.get(url = "https://" + sshd_session['remote_ipaddr'] + "/trustyterm/server_session_setup", params = {'phase': 2, 'tt_session_id': sshd_session['tt_session_id'], 'encrypted_data': cipher_b64, 'signat': signature_b64}, verify = False)
	except requests.excpetions.RequestException as e:
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
	
	signal.signal(signal.SIGINT, sigint_handler)
	
	# Unlinking pending session fifos
	sessions_fifos_cleanup()

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
				session_setup_data = json.loads((session_setup.read()))
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
			
			print(sshd_session)

			#Once we've read from session_setup_fifo we can release the semaphore
			session_setup_sem.release()
			session_setup.close()
			
			global handling_session

			# Here I check if this is a Trustyerm Session (notice that I handle one Session Setup at time regardless of TT or not, since only when I finish to set up a Session I come back reading from Setup FIFO)
			# Moreover, thanks to "handling_session" global var, I do not allow filling of ssh_tt_sid global dictionary, i.e. I allow one HTTP request at time
			global ssh_tt_sids
			if(ssh_tt_sids):
				# Dictionary is not empty, this is a TrustyTerm session
				print("[*] Dictionary is not empty")
				if(sshd_session['ssh_session_id'] not in ssh_tt_sids.keys()):
					# Probabily Proxy gave me a wrong SSH_SID, I have to close
					print("[*] Proxy gave a wrong SSH_SID")
					tt_fifo_write("Close", sshd_session)
					ssh_tt_sids.clear() # Clearing the dictionary
					handling_session -=1 # Since this was a TrustyTerm Session, I received the HTTP request and I incremented this variable, so I have to decrement it
					
				else:
					# I tell SSHD this is a TrustyTerm Session
					print("[*] This is a TrustyTerm session!")
					tt_fifo_write("TT", sshd_session)
					sshd_session['tt_session_id'] = ssh_tt_sids[sshd_session['ssh_session_id']] # Writing TT_SID in ssh_session dictionary
					del ssh_tt_sids[sshd_session['ssh_session_id']] # Remove matching between SSH_SID and TT_SID since it is no longer required
					handling_session -=1 # Since this was a TrustyTerm Session, I received the HTTP request and I incremented this variable, so I have to decrement it

					#Starting thread for the management of the new session
					try:
						print("[*] Creation of a new thread for current session management")
						_thread.start_new_thread(session_management, ("Thread-"+sshd_session['ssh_session_id'], sshd_session,))
						print("[*] New session started from <" + sshd_session['remote_ipaddr'] + ">\n")
					except OSError as e:
						print ("[*] Unable to start a new thread: %s" % e)
			else:
				# Dictionary is empty, this is not a TrustyTerm session
				print("[*] This is not a TrustyTerm Session, telling SSHD to behave normally.")
				tt_fifo_write("NTT", sshd_session)


if __name__ == '__main__':
    main()
