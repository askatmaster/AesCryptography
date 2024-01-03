# AesCryptography


## Description
AesCryptography is a class that provides support for AES (Advanced Encryption Standard) encryption and decryption. It has several methods and constants to perform cryptography operations.

## Constants
`AES_KEY_SIZE` - Represents the size of the AES key in bits.

`AES_BLOCK_SIZE` - Represents the block size used in the AES algorithm.

`IV_SIZE` - Represents the size of the Initialization Vector (IV).

`ITERATIONS` - Represents the number of iterations to be performed.

`BYTE_SIZE` - Represents the size of a single byte in bits.

## Methods

```csharp
public static string Encrypt(string content, string salt)
```
Encrypts the given content using AES encryption algorithm and returns the encrypted content as a base64 encoded string. The input parameters are content (string to be encrypted) and salt (string to assist in encryption).

```csharp
public static string Decrypt(string base64Signature, string salt)
```
Decrypts a base64-encoded signature using a provided salt and returns the decrypted signature as a string. The input parameters are base64Signature (base64-encoded string signature) and salt (string to assist in decryption).

```csharp
private static byte[] AesEncrypt(byte[] bytesToBeEncrypted, byte[] saltBytes)
```
Encrypts the given byte array using AES encryption algorithm and returns the encrypted byte array. The input parameters are bytesToBeEncrypted (byte array to be encrypted) and saltBytes (byte array for salt).

```csharp
private static byte[] AesDecrypt(byte[] bytesToBeDecrypted, byte[] saltBytes)
```
Decrypts the given byte array using AES encryption and returns the decrypted byte array. The input parameters are bytesToBeDecrypted (byte array to be decrypted) and saltBytes (byte array for salt).
This class is used to provide an extra layer of security for sensitive data by encrypting it with AES. Its methods can be used to encrypt and decrypt strings or byte arrays. The class uses a salt (random bytes) to strengthen the encryption process.

**Usage**

This class is used to provide an extra layer of security for sensitive data by encrypting it with AES. Its methods can be used to encrypt and decrypt strings or byte arrays. The class uses a salt (random bytes) to strengthen the encryption process.