namespace OpcodeFinder;

internal class EntryPoint
{
    private static void Main()
    {
        // var sigScanner = new SigScanner(exeBytes);
        var finder = new OpcodeFinder();
        finder.Find();
        Thread.Sleep(-1);
        /*
        var results = sigScanner.FindPattern("00 1B 1B 1B 1B 1B 1B 1B 1B 1B 1B 1B 01 1B");
        if (results.Count == 0)
        {
            Console.WriteLine("Empty");
            return;
        }

        var address = results[0] + 1;
        var offset = BitConverter.ToUInt16(exeBytes, (int)address);
        Console.WriteLine($"0x{address:X} / 0x{exeBytes[address]:X}");*/
    }
}