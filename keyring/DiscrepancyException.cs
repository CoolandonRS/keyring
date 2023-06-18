using System.Security;

namespace CoolandonRS.keyring.Yubikey; 

public class DiscrepancyException : SecurityException {
    public DiscrepancyException() : base() {}
    public DiscrepancyException(string msg) : base(msg) {}
    
}