namespace OpcodeFinder;

internal class EntryPoint
{
    private static void Main()
    {
        var finder = new OpcodeFinder();
// #if RELEASE
        finder.Find();
        finder.SaveOutput();
        Console.ReadKey();
// #endif
    }
}