# OTP Server

A set of programs for Unix acting as server and client, transmitting an unencrypted string and a key string, and returning the original string encrypted using the 'One Time Pad' method via the key. A second set of programs decrypts in the same way.

keygen - Produces a key string of the length provided as the parameter. Supports I/O redirect for writing to a file
Usage: keygen keylength, keygen keylength > outputfile

otp_enc_d - Server program that listens on the port provided as a parameter for its companion client program, otp_enc. Encrypts the provided plaintext string and sends it back to the client.
Usage: otp_enc_d port#

otp_enc - Client program that sends contents of a plaintext file and a key file to its companion server program, otp_enc_d, on the provided port. Receives encrypted string in return. Supports I/O redirect for saving results to a file.
Usage: otp_enc plaintextfile keyfile port#, otp_enc plaintextfile keyfile port > outputfile

otp_dec_d - Server program that listens on the port provided as a parameter for its companion client program, otp_dec. Decrypts the provided encrypted string and sends it back to the client.
Usage: otp_dec_d port#

otp_dec - Client program that sends contents of an encrypted file and a key file to its companion server program, otp_dec_d, on the provided port. Receives plaintext string in return. Supports I/O redirect for saving results to a file.
Usage: otp_dec encryptedfile keyfile port#, otp_dec encryptedfile keyfile port > outputfile