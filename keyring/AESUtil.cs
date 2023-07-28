using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace CoolandonRS.keyring; 

public class AESUtil : EncryptionUtil {
    private Aes aes;
    private byte[] ivKey;
    private int interactionCount;
    private object @lock;
    
    public override byte[] Encrypt(byte[] b) {
        lock (@lock) {
            DeriveIV();
            return aes.EncryptCbc(b, aes.IV);
        }
    }

    public override byte[] Decrypt(byte[] b) {
        lock (@lock) {
            DeriveIV();
            return aes.DecryptCbc(b, aes.IV);
        }
    }

    public (byte[] key, byte[] ivKey) GetSecrets() {
        lock (@lock) {
            if (interactionCount != -1) throw new InvalidOperationException("This AESUtil has already been used. Secrets are not retrievable.");
            return (aes.Key, ivKey);
        }
    }
    
    private static Aes MakeAes(byte[] key) {
        var aes = Aes.Create();
        aes.KeySize = key.Length;
        aes.Key = key;
        return aes;
    }

    private void DeriveIV() {
        interactionCount++; 
        aes.IV = Rfc2898DeriveBytes.Pbkdf2(ivKey, BitConverter.GetBytes(interactionCount), 15000, HashAlgorithmName.SHA256, 16);
    }

    private AESUtil(KeyType keyType, byte[] ivKey, Aes aes, Encoding? encoding = null) : base(keyType, encoding) {
        if (keyType != KeyType.Symmetric) throw new InvalidOperationException("AESUtil only supports symmetric keys");
        this.aes = aes;
        this.ivKey = ivKey;
        this.interactionCount = -1;
    }
    
    /// <summary>
    /// Generates a new AES key to use for the AESUtil
    /// </summary>
    public AESUtil(Encoding? encoding = null) : this(KeyType.Symmetric, RandomNumberGenerator.GetBytes(64), Aes.Create(), encoding) {
    }
    
    public AESUtil(KeyType keyType, byte[] key, byte[] ivKey, Encoding? encoding = null) : this(keyType, ivKey, MakeAes(key), encoding) {
    }
}