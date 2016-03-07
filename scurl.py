import re
from OpenSSL import SSL
from socket import socket

# https://curl.haxx.se/docs/manpage.html

# [--tlsv1] ==> (SSL) Forces curl to use TLS version 1.x when negotiating with a remote TLS server. You can use options --tlsv1.0, --tlsv1.1, and --tlsv1.2 to control the TLS version more precisely (if the SSL backend in use supports such a level of control).

# The behavior of what happens if a callback functions returns False depends on the verification method set: if SSL.VERIFY_NONE was used then the verification chain is not followed but if SSL.VERIFY_PEER was used then a callback function returning False will raise an OpenSSL.SSL.Error exception.
def callback(conn, cert, errno, depth, result):
    if depth == 0 and (errno == 9 or errno == 10):
        return False # or raise Exception("Certificate not yet valid or expired")
    return True

def request(host, path):
    return '''GET %s\r\nHTTP/1.0\r\nHost: %s\r\nConnection: close''' % (path, host)

host = 'www.google.com'
path = '/doodles/about'

# the context is the object that will let us create the SSL Layer on top of a socket in order to get an SSL Connection
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