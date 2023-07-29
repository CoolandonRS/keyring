using System.ComponentModel;

namespace CoolandonRS.keyring.Kyber; 

internal static class Extensions {
    public static int Size(this KyberKeySize size) => (int) size;
    
    // TODO: Should probably be a struct/class instead of this massive tuple
    public static (int n, int k, int q, int eta, (int u, int v) d, Func<double> delta) GetParameters(this KyberKeySize size) {
        return size switch {
            KyberKeySize.Size512  => (256, 2, 3329, 2, (10, 3), () => Math.Pow(2, -178)),
            KyberKeySize.Size768  => (256, 3, 3329, 2, (10, 4), () => Math.Pow(2, -164)),
            KyberKeySize.Size1024 => (256, 4, 3329, 2, (10, 5), () => Math.Pow(2, -174)),
            _ => throw new InvalidEnumArgumentException()
        };
    }
    public static T[] Append<T>(this T[] x, T[] y) {
        var output = new T[x.Length + y.Length];
        x.CopyTo(output, 0);
        y.CopyTo(output, x.Length);
        return output;
    }

    public static (int Start, int End) ToInts(this Range range, int maxIdx) {
        var tuple = (Start: range.Start.ToInt(maxIdx), End: range.End.ToInt(maxIdx));
        if (tuple.Start > tuple.End) throw new IndexOutOfRangeException();
        return tuple;
    }
    
    public static int ToInt(this Index idx, int maxIdx) {
        var val = idx.Value;
        if (idx.IsFromEnd) val = maxIdx - val;
        if (val < 0 || val > maxIdx) throw new IndexOutOfRangeException();
        return val;
    }

    public static Bits ToBits(this byte b) {
        return new Bits(b);
    }

    public static Bits[] ToBits(this byte[] bytes) {
        return bytes.Select(b => new Bits(b)).ToArray();
    }

    public static bool GetFlatIdx(this Bits[] bits, int idx) {
        return bits[idx / 8][idx % 8];
    }
}