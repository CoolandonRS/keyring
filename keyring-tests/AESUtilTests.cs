using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

#pragma warning disable CS0618 // functions marked both internal and obsolete are for unit-tests only, and are not obsolete.

namespace keyring_tests; 

public class AESUtilTests {
    [Test, SuppressMessage("ReSharper", "ObjectCreationAsStatement")]
    public void ConstructorTests() {
        Assert.Throws(typeof(KeyTypeException), () => {
            new AESUtil(KeyType.Public, RandomNumberGenerator.GetBytes(16), Array.Empty<byte>());
        }, "Non-symmetric key success");
    }

    [Test]
    public void EncryptDecrypt() {
        var bMsg = "SecretMessage"u8.ToArray();
        var sMsg = "SecretMessage";
        Assert.Multiple(() => {
            AESUtil? aes = null;
            Assert.DoesNotThrow(() => {
                aes = new AESUtil();
            }, "Empty Constructor failure");
            var bytes = aes!.Encrypt(bMsg);
            var str = aes.EncryptStr(sMsg);
            aes.DecrementInteraction(2);
            Assert.Multiple(() => {
                Assert.That(aes.Decrypt(bytes), Is.EqualTo(bMsg), "Encrypt/Decrypt Bytes Failure");
                Assert.That(aes.DecryptStr(str), Is.EqualTo(sMsg), "Encrypt/Decrypt String Failure");
                Assert.That(() => {
                    if (aes.Decrypt(bytes) == bMsg) throw new Exception();
                }, Throws.Exception, "Successful Decryption without IV sync");
            });
        });
    }
}