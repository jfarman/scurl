## Synopsis

Scurl is a simplified version of the command line utility curl that makes HTTPS requests using the pyOpenSSL library.

## Usage

Scurl can be invoked as follows:

$ ./scurl [options] URL

For example, the following would send an HTTPS request to the specified URL using a TLSV1.1 protocol.

$ ./scurl --tlsv1.1 https://sha256.badssl.com/

## Motivation

This project was implemented as part of Dan Boneh's Cryptography course at Stanford University. To learn more about this assignment, you can access the assignment description [here.](https://crypto.stanford.edu/~dabo/cs255/hw_and_proj/proj2.pdf)