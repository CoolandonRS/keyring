using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace keyring_tests;

public class RSAUtilTests {
    // Public/Private test keypair
    private const string privatePEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl7wDGkOwqtr4X\nprmYYE79dhyks2vaXvNzlC0tB1l+Z1foLoiywKFnQ1SyzJUlYESFvRePejWhvPmU\n/54PXVUBR8vDrsQm1c+Cvu7GCOeufPyjvS2lFz6KxbdhmUnP6L+P3pOUTl8w0h3m\nB+I+4poxz6l5s88b0Fk4lXgdnrDG3dcHALx/qpP2FrW730WbfFkRnNH49QN+2weW\nCV8UlD12fsekPR+K0YxZXudpgOyZ63DcOqvbywfzyDYZ4hRqe2mvsfUeuuPgRW0y\nd/NF+M0lH8wdbxrM7x5fgS6ZCWTpLDnn/JjU2rCHjQZQxRw9Xi5OSmg+wYDu/gHy\nj2h3+zCbAgMBAAECggEACJ1I0rDcDIz3f24rZ8q62b5pAZqYTc+XdKJLr3EYkfm2\n1ESeL3wqpPFs6JS7ECQC9VfPbPvGOa2q3gkLNqGnc8KQxImX1gBMSUMKTa5RViYC\nTlSC6yAyzKzeYVW+QZSZZVRZIF4/44lKU2feCgUPm5MRVFJ5Emjq84dm+KVavhLZ\neYGQdkLvEMpj7kjzkiRoaA5prt+0s9Wi3MCIY/uWQa7eKVagPQ2syGr940LZU/Yy\newNqj9H+lWrqWkDpWmzHRoJp1J1kBTTmHz589vU3fRHqchhVRhin49xtfHlinhLU\naRXfptUL8uxNbbX7Oq9K3H0rh06XUgeyDa1o8br4UQKBgQDdA1FDjaNmeHFecN6B\nEQ6RiKNhQ6J5eEakIivtiN7vWmPdhursSnbfCA4rQBgZNEXhC1w+mHJfL7h1/eMu\nLS1zbANtGB6W+Tike3Ng/51MsMQB5amdqHEOeXJKN6VD7Tx4DZkdJKRmtTtx2fnI\ngqor/stx1pFfrUlZoduZK/RmiQKBgQDAM4/SpccSUuyKlSaZuIEADrGg3fL87jNf\notyhVgl1V0lZzxwoY/NOYTVfuEooYpj2h/d24FXlISYqNq/ZX2381sd2ENoaGBBe\n9qCIiPVdOC8ut0YgL47xSUdyxYxtRUOqlZ7k8xmpm4XyhCGo52IN0GJLODMK0BAy\nO1LgMN7VAwKBgQCBIVYSpSfKUCbU6hdmy6N6bp4ezxiX5ilH7ttBns26hVKB9Tk/\nM8a+SwOUS4+I8ly9vxh3TjTM3qHk9qEMssKyhHKABC6jQRvSJnrkOpUaYNE01o3C\nms7riRO4v0hlJrBE6JUETQttIwiHXbcuawGoUOdnLNmlUCbiIsqedOsIGQKBgBlF\nbk6rH26oWpOqIsYpfUStqetV44IgK78SYeIQtvOnw2w8kB47bh1LKMJqL835kNUx\ncXc+7exPnH4GbL6vDn4lG1rJwnOV4GksElWBdImKPqHs1RqcRjYxhWRw1xLy/X+r\nZpYB5MjpOwZ1GxvjOIBKevIa9JMiYk7IgBAcPOBTAoGADThTqtr1f3iDL6ZSjfl9\nmD+R8/Ht+V81/g3E+BwXmn32HfunDHaaFF32ocNHSduod6IWFgqwpJyrGhK3qelc\nO9efmH5bxZhNUrKHn0rAPSRiogo+c6n2GaLqA4y5wp/5xcVJJUmktxAg1OA0qqRz\n/xUtOXGbxv/bCp9YpY0olx0=\n-----END PRIVATE KEY-----";
    private const string publicPEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApe8AxpDsKra+F6a5mGBO\n/XYcpLNr2l7zc5QtLQdZfmdX6C6IssChZ0NUssyVJWBEhb0Xj3o1obz5lP+eD11V\nAUfLw67EJtXPgr7uxgjnrnz8o70tpRc+isW3YZlJz+i/j96TlE5fMNId5gfiPuKa\nMc+pebPPG9BZOJV4HZ6wxt3XBwC8f6qT9ha1u99Fm3xZEZzR+PUDftsHlglfFJQ9\ndn7HpD0fitGMWV7naYDsmetw3Dqr28sH88g2GeIUantpr7H1Hrrj4EVtMnfzRfjN\nJR/MHW8azO8eX4EumQlk6Sw55/yY1Nqwh40GUMUcPV4uTkpoPsGA7v4B8o9od/sw\nmwIDAQAB\n-----END PUBLIC KEY-----";
    private RSAUtil prv;
    private RSAUtil pub;

    [OneTimeSetUp]
    public void SingleSetUp() {
        prv = new RSAUtil(KeyType.Private, privatePEM);
        pub = new RSAUtil(KeyType.Public, publicPEM);
    }

    [Test]
    [SuppressMessage("ReSharper", "ObjectCreationAsStatement")]
    public void ConstructorErrors() {
        Assert.Multiple(() => {
            Assert.Throws(typeof(InvalidOperationException), () => {
                new RSAUtil(KeyType.Symmetric, "");
            }, "Symmetric Key Success");
            Assert.Throws(typeof(ArgumentException), () => {
                new RSAUtil(KeyType.Private, "");
            }, "Invalid PEM Success");
            Assert.Throws(typeof(ArgumentException), () => {
                new RSAUtil(KeyType.Private, publicPEM);
            }, "Public/Private Mismatch Success");
        });
    }

    [Test]
    public void EncryptDecrypt() {
        Assert.Multiple(() => {
            var bytes = pub.Encrypt("SecretMessage"u8.ToArray());
            var str = pub.EncryptStr("SecretMessage");
            Assert.Multiple(() => {
                Assert.That(prv.Decrypt(bytes), Is.EqualTo("SecretMessage"u8.ToArray()), "Encrypt/Decrypt Bytes Failure");
                Assert.That(prv.DecryptStr(str), Is.EqualTo("SecretMessage"), "Encrypt/Decrypt String Failure");
            });
        });
    }
}