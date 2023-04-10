using System.Security.Cryptography;
using System.Text;

namespace CoolandonRS.keyring;

/// <summary>
/// Tool for using RSA Encryption/Decryption
/// </summary>
public class RSAUtil {
    private RSACryptoServiceProvider provider;
    private readonly KeyType keyType;
    private Encoding encoding;

    /// <summary>
    /// Encrypts data using the stored key(s)
    /// </summary>
    /// <param name="dat">Data to encrypt</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(byte[] dat) {
        return provider.Encrypt(dat, false);
    }

    /// <summary>
    /// Encodes and encrypts a string using the chosen encoding and stored key(s)
    /// </summary>
    /// <param name="str">String to encode and encrypt</param>
    /// <returns>Encrypted data</returns>
    public byte[] EncryptStr(string str) {
        return Encrypt(encoding.GetBytes(str));
    }

    /// <summary>
    /// Decrypts data using the stored key(s)
    /// </summary>
    /// <param name="dat">Data to decrypt</param>
    /// <returns>Decrypted Data</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public byte[] Decrypt(byte[] dat) {
        if (keyType != KeyType.Private) throw new InvalidOperationException("Cannot decrypt if keyType is not private");
        return provider.Decrypt(dat, false);
    }

    /// <summary>
    /// Decrypts data and encodes it into a string using the chosen encoding and stored key(s)
    /// </summary>
    /// <param name="dat">Encrypted data</param>
    /// <returns>Decrypted string</returns>
    public string DecryptStr(byte[] dat) {
        return encoding.GetString(Decrypt(dat));
    }
    
    /// <summary>
    /// Creates an instance of RSAUtil
    /// </summary>
    /// <param name="keyType">The type of key you are providing</param>
    /// <param name="pemContents">The contents of the PEM file</param>
    /// <param name="encoding">The text encoding to use for strings</param>
    /// <exception cref="InvalidOperationException">If you provide a symmetric key</exception>
    public RSAUtil(KeyType keyType, string pemContents, Encoding? encoding = null) {
        if (keyType == KeyType.Symmetric) throw new InvalidOperationException("RSAUtil does not support symmetric keys");
        // ReSharper disable once LocalVariableHidesMember // Intentional
        var provider = new RSACryptoServiceProvider();
        provider.ImportFromPem(pemContents);
        if (keyType == KeyType.Private && provider.PublicOnly) throw new ArgumentException("keyType reported as private; no private key found.");
        this.keyType = keyType;
        this.provider = provider;
        this.encoding = encoding ?? Encoding.UTF8;
    }
}