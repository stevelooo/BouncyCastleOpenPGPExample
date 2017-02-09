# Bouncy Castle OpenPGP Example
Sample code of how to use Bouncy Castle library to perform PGP encrypt, decrypt, sign and verify operations.

There are a lot of example code about how to encrypt or decrypt. However, there is hardly an example of how to "encrypt then sign" and "sign then encrypt" in one operation.
I was inspired by seeing [John Opincar's Bouncy Castle blog](https://jopinblog.wordpress.com/2008/06/23/pgp-single-pass-sign-and-encrypt-with-bouncy-castle/) in C#. It helps me to work out the puzzle.
I would like to share what I found, hopefully, it will save a lot of times for others.