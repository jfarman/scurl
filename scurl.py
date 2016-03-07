import sys
import re
from OpenSSL import SSL
from socket import socket
from optparse import OptionParser
from urlparse import urlparse

# https://curl.haxx.se/docs/manpage.html

# [--tlsv1] ==> (SSL) Forces curl to use TLS version 1.x when negotiating with a remote TLS server.
# You can use options --tlsv1.0, --tlsv1.1, and --tlsv1.2 to control the TLS version more precisely,
# provided that the SSL backend in use supports such a level of control).

# The behavior of what happens if a callback functions returns False depends on the verification method set.
# If SSL.VERIFY_NONE was used then the verification chain is not followed.
# if SSL.VERIFY_PEER was used then a callback function returning False will raise an OpenSSL.SSL.Error exception.
def callback(conn, cert, errno, depth, result):
    if depth == 0 and (errno == 9 or errno == 10):
        return False # or raise Exception("Certificate not yet valid or expired")
    return True

def initOptionParser():
	parser.add_option("--tlsv1.0", action="store_const", const="tlsv1.0", dest="protocol", default="--tlsv1.2", help="todo")
	parser.add_option("--tlsv1.1", action="store_const", const="tlsv1.1", dest="protocol", default="--tlsv1.2", help="todo")
	parser.add_option("--tlsv1.2", action="store_const", const="tlsv1.2", dest="protocol", default="--tlsv1.2", help="todo")
	parser.add_option("--sslv3", action="store_const", const="sslv3", dest="protocol", default="--tlsv1.2", help="todo")
	parser.add_option("--3", action="store_const", const="3", dest="protocol", default="--tlsv1.2", help="todo")

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

parser = OptionParser()
initOptionParser()
(options, args) = parser.parse_args()

print options 	# also: print args

url = urlparse(args[0])
print url

if url.scheme == 'https':
	print "yay"
else:
	sys.exit('Error!')

host = 'www.google.com'
path = '/doodles/about'

# TODO: URL PARSING
# TODO: STRING DELIMITING FOR CIPHERS LIST
# TODO: pinned public key option override, check for none

context = SSL.Context(SSL.TLSv1_METHOD)
# context.set_options(SSL.OP_NO_SSLv2)					# ?? DO I NEED TO DO THIS?
context.set_verify(SSL.VERIFY_NONE, callback)			# ?? WHICH VERFICATION MODE (sets verification mode & callback fn to call when verifying)
# context.load_verify_locations(ca_file, ca_path)		# ?? WHAT IS GOING ON HERE

s = socket()											# ?? (socket.AF_INET, socket.SOCK_STREAM)
# s.settimeout(5)										# ?? do i need to do this? try catch
connection = SSL.Connection(context, s)
# connection.connect((ip_addr, port))					# ?? where do you get IP ADDRESS AND PORT ("www.facebook.com",443) ??
connection.connect((host,443))
connection.do_handshake()								# ?? TRY CATCH FOR HANDSHAKE

connection.sendall(request(host, path))
print connection.read(1024)

# set_cipher_list
# SSL.SysCallError occurs from a recv() call

#connection.sendall(req)
#print connection.read(1024)

# TRY CATCH FOR HANDSHAKE
# try: 
#	connection.do_handshake()
# except SSL.WantReadError:
# print "Timeout"
# quit()