namespace CoolandonRS.keyring; 

public class KeyTypeException : InvalidOperationException {
    public KeyTypeException() : base() {}
    public KeyTypeException(string msg) : base(msg) {}

}