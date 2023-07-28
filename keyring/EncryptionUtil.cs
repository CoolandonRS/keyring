using System.Security.Cryptography;
using System.Text;

namespace CoolandonRS.keyring; 

public abstract class EncryptionUtil {
    protected readonly KeyType keyType;
    protected readonly Encoding encoding;
    
    /// <summary>
    /// Encrypts data using the stored key(s)
    /// </summary>
    /// <param name="dat">Data to encrypt</param>
    /// <returns>Encrypted data</returns>
    public abstract byte[] Encrypt(byte[] b);

    public virtual byte[] EncryptStr(string s) => Encrypt(encoding.GetBytes(s));

    /// <summary>
    /// Decrypts data using the stored key(s)
    /// </summary>
    /// <param name="dat">Data to decrypt</param>
    /// <returns>Decrypted Data</returns>
    /// <exception cref="InvalidOperationException">Unable to decrypt</exception>
    public abstract byte[] Decrypt(byte[] b);

    public virtual string DecryptStr(byte[] b) => encoding.GetString(Decrypt(b));

    public KeyType GetKeyType() => keyType;

    protected EncryptionUtil(KeyType type, Encoding? encoding) {
        this.keyType = type;
        this.encoding = encoding ?? Encoding.UTF8;
    }
}