using System.Security.Cryptography;
using System.Text;

namespace AesCryptography;

/// <summary>
/// Provides cryptographic operations such as encryption and decryption using AES algorithm.
/// </summary>
public class AesCryptography
{
    /// <summary>
    /// Represents the size of the AES key in bits.
    /// </summary>
    private const int AES_KEY_SIZE = 256;

    /// <summary>
    /// The AES_BLOCK_SIZE is a constant integer variable that represents the block size used in the Advanced Encryption Standard (AES) algorithm.
    /// The AES algorithm is a symmetric encryption algorithm used to encrypt and decrypt data. It operates on blocks of data, and the block size specifies the number of bits in each data
    /// block.
    /// In this case, AES_BLOCK_SIZE is set to 128, which means that each data block will consist of 128 bits (16 bytes).
    /// </summary>
    private const int AES_BLOCK_SIZE = 128;

    /// <summary>
    /// The constant value representing the size of the initialization vector (IV).
    /// </summary>
    /// <remarks>
    /// The IV is a fixed-size random or pseudo-random input used in symmetric and asymmetric encryption algorithms.
    /// This value is used to initialize the cipher and ensure different encryption results even for the same plaintext.
    /// The size of the IV is typically measured in bytes.
    /// </remarks>
    private const int IV_SIZE = 16;

    /// <summary>
    /// The number of iterations to be performed.
    /// </summary>
    private const int ITERATIONS = 10000;

    /// <summary>
    /// Represents the size of a single byte in bits.
    /// </summary>
    private const int BYTE_SIZE = 8;

    /// <summary>
    /// Encrypts the given content using AES encryption algorithm.
    /// </summary>
    /// <param name="content">The content to be encrypted.</param>
    /// <param name="salt">The salt used for encryption.</param>
    /// <returns>The encrypted content as a base64 encoded string.</returns>
    public static string? Encrypt(string content, string salt)
    {
        var bytesToBeEncrypted = Encoding.UTF8.GetBytes(content);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        try
        {
            var bytesEncrypted = AesEncrypt(bytesToBeEncrypted, saltBytes);

            return Convert.ToBase64String(bytesEncrypted);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }


    /// <summary>
    /// Decrypts a base64-encoded signature using a provided salt.
    /// </summary>
    /// <param name="base64Signature">The base64-encoded signature to be decrypted.</param>
    /// <param name="salt">The salt used for decryption.</param>
    /// <returns>The decrypted signature as a string.</returns>
    public static string? Decrypt(string base64Signature, string salt)
    {
        var bytesToBeDecrypted = Convert.FromBase64String(base64Signature);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        try
        {
            var bytesDecrypted = AesDecrypt(bytesToBeDecrypted, saltBytes);

            return Encoding.UTF8
                           .GetString(bytesDecrypted)
                           .TrimEnd('\0');
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>
    /// Encrypts the given byte array using AES encryption.
    /// </summary>
    /// <param name="bytesToBeEncrypted">The byte array to be encrypted.</param>
    /// <param name="saltBytes">The salt bytes used for key generation.</param>
    /// <returns>The encrypted byte array.</returns>
    private static byte[] AesEncrypt(byte[] bytesToBeEncrypted, byte[] saltBytes)
    {
        using var aes = Aes.Create();
        var key = new Rfc2898DeriveBytes(saltBytes, saltBytes, ITERATIONS, HashAlgorithmName.SHA256);

        aes.KeySize = AES_KEY_SIZE;
        aes.BlockSize = AES_BLOCK_SIZE;
        aes.Key = key.GetBytes(aes.KeySize / BYTE_SIZE);
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;

        using var memoryStream = new MemoryStream();
        memoryStream.Write(aes.IV, 0, aes.IV.Length);

         using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write)) 
             cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
         
         return memoryStream.ToArray();

    }

    /// <summary>
    /// Decrypts the given byte array using AES encryption algorithm.
    /// </summary>
    /// <param name="bytesToBeDecrypted">The byte array to be decrypted.</param>
    /// <param name="saltBytes">The salt bytes used for key derivation.</param>
    /// <returns>The decrypted byte array.</returns>
    private static byte[] AesDecrypt(byte[] bytesToBeDecrypted, byte[] saltBytes)
    {
        using var aes = Aes.Create();
        var key = new Rfc2898DeriveBytes(saltBytes, saltBytes, ITERATIONS, HashAlgorithmName.SHA256);

        aes.KeySize = AES_KEY_SIZE;
        aes.BlockSize = AES_BLOCK_SIZE;
        aes.Key = key.GetBytes(aes.KeySize / BYTE_SIZE);
        aes.Mode = CipherMode.CBC;

        using var memoryStream = new MemoryStream(bytesToBeDecrypted);

        var iv = new byte[aes.BlockSize / BYTE_SIZE];
        var bytesRead = memoryStream.Read(iv, 0, iv.Length);

        if (bytesRead < IV_SIZE)
            throw new CryptographicException("Insufficient data to read IV from");

        aes.IV = iv;

        using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
        {
            using var resultStream = new MemoryStream();

            cryptoStream.CopyTo(resultStream);

            return resultStream.ToArray();
        }
    }
}