using System.CodeDom.Compiler;
using System.Security.Cryptography;
using System.Text;

namespace CoolandonRS.keyring;

/// <summary>
/// Tool for using RSA Encryption/Decryption
/// </summary>
public class RSAUtil : EncryptionUtil {
    private RSACryptoServiceProvider provider;
    private Encoding encoding;
    
    public override byte[] Encrypt(byte[] dat) {
        return provider.Encrypt(dat, false);
    }
    
    public override byte[] Decrypt(byte[] dat) {
        if (keyType != KeyType.Private) throw new InvalidOperationException("Cannot decrypt if keyType is not private");
        return provider.Decrypt(dat, false);
    }

    /// <summary>
    /// Creates an instance of RSAUtil
    /// </summary>
    /// <param name="keyType">The type of key you are providing</param>
    /// <param name="pemContents">The contents of the PEM file</param>
    /// <param name="encoding">The text encoding to use for strings</param>
    /// <exception cref="InvalidOperationException">If you provide a symmetric key</exception>
    public RSAUtil(KeyType keyType, string pemContents, Encoding? encoding = null) : base(keyType, encoding) {
        if (keyType == KeyType.Symmetric) throw new InvalidOperationException("RSAUtil does not support symmetric keys");
        // ReSharper disable once LocalVariableHidesMember // Intentional
        var provider = new RSACryptoServiceProvider();
        provider.ImportFromPem(pemContents);
        if (keyType == KeyType.Private && provider.PublicOnly) throw new ArgumentException("keyType reported as private; no private key found.");
        this.provider = provider;
    }
}