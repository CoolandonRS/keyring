namespace CoolandonRS.keyring.Yubikey; 

public class YubicoErrorException : InvalidOperationException {
    internal YubicoErrorException(YubiOTP.YubicoApiStatus status) : base(status.ToString()) {}
}