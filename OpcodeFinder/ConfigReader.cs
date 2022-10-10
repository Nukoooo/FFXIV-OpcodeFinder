using Newtonsoft.Json;

namespace OpcodeFinder;

internal enum ReadType
{
    None,
    Uint8,
    Uint16,
    Uint32,
    Uint64
}

internal enum ActionType
{
    None,
    ReadThenCrossReference,
    CrossReference
}

internal enum JumpTableType
{
    None,
    Direct,
    Indirect
}

internal class SignatureInfo
{
    public ActionType ActionType = ActionType.None;
    public Dictionary<int, string>? DesiredValues = null;
    public int FunctionSize = 0;
    public JumpTableType JumpTableType = JumpTableType.None;
    public string Name;
    public int Offset = 0;
    public ReadType ReadType = ReadType.None;
    public int? ReferenceCount = null;
    public string Signature;
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
        if (!File.Exists($"./{FileName}")) throw new FileNotFoundException($"Cannot find file {FileName}");

        return JsonConvert.DeserializeObject<Config>(File.ReadAllText($"./{FileName}"));
    }
}