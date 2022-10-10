using Newtonsoft.Json;

namespace OpcodeFinder;

internal enum ReadType : int
{
    None,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
}

internal enum ActionType : int
{
    None,
    ReadThenCrossReference,
    CrossReference,
}

internal enum JumpTableType : int
{
    None,
    Direct,
    Indirect,
}

internal class SignatureInfo
{
    public string Signature;
    public string Name;
    public int Offset = 0;
    public int FunctionSize = 0;
    public ReadType ReadType = ReadType.None;
    public ActionType ActionType = ActionType.None;
    public int? ReferenceCount = null;
    public JumpTableType JumpTableType = JumpTableType.None;
    public Dictionary<int, string>? DesiredValues = null;
    public List<SignatureInfo>? SubInfo = null;
}

internal class Config
{
    public string GamePath;
    public List<SignatureInfo> Signatures;
}

internal class ConfigReader
{
    private const string FileName = "config.json";

    public static Config? Load()
    {
        if (!File.Exists($"./{FileName}"))
        {
            throw new FileNotFoundException($"Cannot find file {FileName}");
        }
        
        return JsonConvert.DeserializeObject<Config>(File.ReadAllText($"./{FileName}"));
    }
}