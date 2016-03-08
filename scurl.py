#!/usr/bin/python
# -*- encoding: utf-8 -*-

import sys
import re
from OpenSSL import SSL
from OpenSSL import crypto
from socket import socket
from optparse import OptionParser
from urlparse import urlparse

# https://curl.haxx.se/docs/manpage.html

# *. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .* *. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*

def initOptionParser():
	parser.add_option("--tlsv1.0", action="store_const", const="tlsv1.0", dest="protocol", default="tlsv1.2", help="todo")
	parser.add_option("--tlsv1.1", action="store_const", const="tlsv1.1", dest="protocol", default="tlsv1.2", help="todo")
	parser.add_option("--tlsv1.2", action="store_const", const="tlsv1.2", dest="protocol", default="tlsv1.2", help="todo")
	parser.add_option("--sslv3", "-3", action="store_const", const="sslv3", dest="protocol", default="tlsv1.2", help="todo")

	# --crlfile <file>
	# (HTTPS/FTPS) Provide a file using PEM format with a Certificate Revocation List that may specify peer certificates that
	# are to be considered revoked. If this option is used several times, the last one will be used.
	parser.add_option("--crlfile", action="store", dest="crlfile")

	# --cacert <CA certificate>
	# (SSL) Tells curl to use the specified certificate file to verify the peer. The file may contain multiple CA certificates.
	# The certificate(s) must be in PEM format. Normally curl is built to use a default file for this, so this option is
	# typically used to alter that default file.
	parser.add_option("--cacert", action="store", dest="cacert")

	# --allow-state-certs <N>
	# Tells scurl to accept a certificate C as valid if (a) C is an otherwise valid certificate that has expired
	# and (b) C expired within the past N days. The argument N to this option must be a nonnegative integer.
	# If this option is used several times, the last one will be used.
	parser.add_option("--allow-state-certs", action="store", dest="expiration")

	# --ciphers <list of ciphers>
	# (SSL) Specifies which ciphers to use in the connection. The list of ciphers must specify valid ciphers.
	# Read up on SSL cipher list details on this URL: https://www.openssl.org/docs/apps/ciphers.html
	parser.add_option("--ciphers", action="store", dest="ciphers")

	# --pinnedpublickey (PPK) <file> (the path to a public key in PEM format)
	# If specified, scurl will only connect to a server if the servers TLS cert is exactly the one contained in the specified file.
	# Must use the SHA-256 cert fingerprint functionality built into pyOpenSSL to compare the servers cert to the PPK.
	# If the server sends the scurl client a certificate chain, you should only check that the leaf certificate matches
	# the pinned public key certificate - ignore any CA certificates that the server sends.
	# This option overrides the --cacert and --crlfile options. If this option is used several times, the last one will be used.
	parser.add_option("--pinnedpublickey", action="store", dest="ppkfile")
	
	return

def request(host, path):
    return '''GET %s\r\nHTTP/1.0\r\nHost: %s\r\nConnection: close''' % (path, host)

def printCertificateInfo(cert):
	name = cert.get_issuer() 
	print "--------------------------------------------------------"
	print cert.get_pubkey()
	print cert.get_serial_number()
	print cert.get_subject()
	print cert.get_version()
	print cert.has_expired()
	print "--------------------------------------------------------"
	print name.countryName
	print name.stateOrProvinceName
	print name.organizationName
	print "--------------------------------------------------------"
	return

def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print('Got certificate: ' + commonname)
    return ok

# The behavior when callback returns false depends on the verification method set.
# If SSL.VERIFY_NONE was used then the verification chain is not followed.
# if SSL.VERIFY_PEER was used then a callback function returning False will raise an OpenSSL.SSL.Error exception.
def callback(conn, cert, errnum, depth, result):
	certsubject = crypto.X509Name(cert.get_subject())
	commonname = certsubject.commonName
	print('Got certificate: ' + commonname)

	regex = commonname.replace('.', r'\.').replace('*',r'.*') + '$'
	match = re.search(regex, url.netloc)
	if not match:
		return False

	if depth == 0 and (errnum == 9 or errnum == 10):
		return False # or raise Exception("Certificate not yet valid or expired")
	return True

	# printCertificateInfo(cert)

	       #if preverifyOK:
            #if self.hostname != x509.get_subject().commonName:
                #return False
        #return preverifyOK
    
    # cert = connection.get_peer_certificate()
    # common_name = cert.get_subject().commonName.decode()
    # print common_name
    # regex = common_name.replace('.', r'\.').replace('*',r'.*') + '$'
    # if re.matches(regex, host_name):
    	#print "yay"
    #else:
    	#print "boo"

# *. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .* *. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*. · ° ▪ ° · .*

protocols = {'tlsv1.0': SSL.TLSv1_METHOD, 'tlsv1.1': SSL.TLSv1_1_METHOD, 'tlsv1.2': SSL.TLSv1_2_METHOD, 'sslv3' : SSL.SSLv3_METHOD}

parser = OptionParser()
initOptionParser()
(options, args) = parser.parse_args()

print options 	# also: print args

url = urlparse(args[0])
print url

if url.scheme != 'https':
	sys.exit('Error!')

# TODO: STRING DELIMITING FOR CIPHERS LIST; set_cipher_list()
# TODO: pinned public key option override, check for none
# TODO: implement SNI
# TODO: check for revoked certs
# TODO: Connection.get_peer_certificate() VS Connection.get_peer_cert_chain()
# TODO: Figure out what happens when SSL.SysCallError occurs from a recv() call [???]
# TODO: Disabling Old Versions of SSL/TLS?

context = SSL.Context(protocols[options.protocol])

# [???] Are there any options I need to set? What does load_verify_locations mean?
# context.set_options(SSL.OP_NO_SSLv2)
# context.load_verify_locations(ca_file, ca_path)

# [???] If no server certificate is sent, because an anonymous cipher is used, SSL_VERIFY_PEER is ignored.
context.set_verify(SSL.VERIFY_PEER, callback)			

# [???] Do I need to do <<s.settimeout(5)>>? What about socket arguments, ie <<socket(socket.AF_INET, socket.SOCK_STREAM)>>?
# [???] What about try catch for socket connection (or for handshake), ie <<except SSL.WantReadError>>?
# [???] Should I specify the default port (ie port 443)?

# [???] For TCP, is socket.SOCK_STREAM necessary?
# [???] Closing the connection?
s = socket()
connection = SSL.Connection(context, s)
connection.connect((url.netloc,443))
try:
	connection.do_handshake()
except SSL.Error:
	sys.exit('Error!')

connection.sendall(request(url.netloc, url.path))
# [???] What terminates this loop?
print connection.read(1024)

