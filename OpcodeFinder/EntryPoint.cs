namespace OpcodeFinder;

internal class EntryPoint
{
    private static void Main()
    {
        var finder = new OpcodeFinder();
        finder.Find();
        finder.SaveOutput();
        Console.Read();
    }
}