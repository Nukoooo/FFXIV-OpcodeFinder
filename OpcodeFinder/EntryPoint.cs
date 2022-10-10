namespace OpcodeFinder;

internal class EntryPoint
{
    private static void Main()
    {
        var finder = new OpcodeFinder();
        finder.Find();

        Console.Read();
    }
}