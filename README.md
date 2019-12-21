# eAES
 The RHX symmetric cipher (eAES)
The RHX (Rijndael Hash eXtension) cipher, is a hybrid of Rijndael (AES) and a cryptographically strong pseudo-random generator function.
The cryptographic KDF, is used to generate the round keys for the Rijndael rounds function, enabling the safe addition of increased mixing rounds, 
and replacing the differentially-weak native Rijndael key-schedule expansion function.
The cipher also increases the number of mixing rounds from 14 used by AES-256, to 22 used by RHX-256, twice the best known classical computer attack.
The cipher has a 512-bit key configuration, which uses 30 rounds of mixing. 
There are attacks now being proposed, that strongly indicate this larger key sizes will be necessary, against future quantum-based attacks on symmetric ciphers.

The default extension used by this cipher is the Keccak cSHAKE extended output function (XOF).
The fallback generator is HKDF(HMAC(SHA2)) Expand.
Both genertors are implemented in 256 and 512-bit forms of those functions, and are implemented correlating to the input cipher-key size.
The cipher code names are based on which generator is used; RHX for Rijndael HKDF eXtension, and RSX for Rijndael SHAKE eXtension, 
with the ciphers formal name now being 'eAES', or extended AES.
The cipher has four modes, AES128 and AES256, which are the standard AES configurations, and the two extended modes, RSX/RHX-256 and RSX/RHX-512.
In extended mode, the key schedules round-key expansion function has been replaced by cSHAKE or HKDF(HMAC(SHA2)), and can now can safely produce a larger round-key array,
unlocking an increased number of mixing rounds, and preventing many serious forms of attack on the Rijndael cipher.

This is a 'tweakable cipher', the initialization parameters for the cipher include an info parameter.
Internally, the info parameter is used to customize the cSHAKE output, using the 'name' parameter to pre-initialize the SHAKE state. 
If using the HKDF extension, this parameter is used as the HKDF Expand 'info' parameter, added to the input key and internal counter, and processed by the HMAC pseudo-random function.
The default value for this information parameter is the cipher name, the extension type H or S, the size of the extension generators security in bits, 
and the size of the key in bits, as a 16-bit Little Endian integer, ex. RHX using the SHAKE extension, and a 256-bit key would be: RHXS25610.
The info parameter can be tweaked, using a user defined string. This tweak can be used as a secondary 'domain key', 
or to differentiate cipher-text output from other implementations.

Implementation
The base cipher, Rijndael, and the extended form of the cipher, can operate using one of the four provided cipher modes of operation:
Block cipher counter mode with Hash Based Authentication (HBA),
an AEAD mode that uses KMAC or HMAC to authenticate a cipher-text.
Electronic Code Book mode (ECB), which can be used for testing or creating more complex algorithms, 
a segmented integer counter (CTR), and the Cipher Block Chaining mode (CBC). 
GCM will soon be added to this implementations modes.
This implementation has both a C reference, and an implementation that uses the AES-NI instructions that are used in the AES and RHX cipher variants. 
The AES-NI implementation can be enabled by adding the RHX_AESNI_ENABLED constant to your preprocessor definitions. 
The RHX key expansion function can be changed to the HKDF implementation by adding the RHX_HMAC_EXTENSION to the preprocessor list.
The HBA implementation mirrors this change, using HMAC in legacy mode, or KMAC in cSHAKE mode.
The AES128 and AES256 implementations along with the CBC, CTR, and CBC modes are tested using vectors from NIST SP800-38a. 
See the documentation and the rhx_kat.h tests for usage examples.

SP800-38a: <a href="http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">Block Cipher Modes of Operations</a>

Towards post-quantum symmetric cryptography: <a href="https://eprint.iacr.org/2019/553>eAES</a>

Towards Post-Quantum Secure Symmetric Cryptography: <a href="https://eprint.iacr.org/2019/1208>A Mathematical Perspective</a>
