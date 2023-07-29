namespace CoolandonRS.keyring.Kyber; 

internal class Bits {
    private byte b;
    
    public bool this[int i] {
        get {
            if (i > 7) throw new IndexOutOfRangeException();
            return (b & (1 << i)) != 0;
        }
        set {
            if (i > 7) throw new IndexOutOfRangeException();
            if (value) {
                b |= (byte)  (1 << i);
            } else {
                b &= (byte) ~(1 << i);
            }
        }
    }

    public bool[] this[Range range] {
        get {
            var ints = range.ToInts(7);
            var output = new bool[ints.End - ints.Start]; 
            for (var i = 0; i < output.Length; i++) {
                output[i] = this[i + ints.Start];
            }
            return output;
        }
    }

    public bool[] ToArray() => this[..];

    public byte ToByte() => b;

    public override string ToString() {
        return string.Concat(this[..].Select(v => v ? "1" : "0"));
    }

    public Bits(byte b) {
        this.b = b;
        var ns = new int[] { 1, 2, 3, 4 };
    }
}