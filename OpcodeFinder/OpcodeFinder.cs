using System.Globalization;
using Iced.Intel;

namespace OpcodeFinder;

internal class OpcodeFinder
{
    private const int MagicOffset = 0xC00;
    private readonly byte[] _arrayData;
    private readonly SigScanner _scanner;
    private readonly List<SignatureInfo> _signatures;

    private readonly List<int> offsetList = new()
                                            {
                                                0,
                                                0xC00,
                                                -0xC00
                                            };

    public OpcodeFinder()
    {
        var config = ConfigReader.Load();

        if (!File.Exists(config.GamePath))
            throw new FileNotFoundException($"Cannot find ffxiv_dx11.exe. Your path from config.json: {config.GamePath}");

        _arrayData = File.ReadAllBytes(config.GamePath);

        _scanner = new SigScanner(_arrayData);

        _signatures = config.Signatures;
    }

    private void GetReference(string pattern, int count)
    {
        var result = _scanner.FindPattern(pattern);
        if (result.Count == 0)
            return;

        ulong functionStart = 0;

        for (var i = 0; i < count; i++)
        {
            var xrefs = _scanner.GetCrossReference((int)(i == 0 ? result[0] : functionStart));
            var curAddr = xrefs[0];
            if (i != count - 1)
                for (var j = 0; j <= 0x50; j++)
                {
                    if (_arrayData[curAddr - (ulong)j] != 0xCC)
                        continue;
                    curAddr -= (ulong)(j - 1);
                    functionStart = curAddr;
                    break;
                }
            else
                functionStart = curAddr;

            Console.WriteLine($"{i}: 0x{functionStart + MagicOffset:X} / 0x{functionStart:X}");
        }
    }

    public void Find()
    {
        foreach (var signature in _signatures)
        {
            if (signature.SubInfo == null)
            {
                FindOffsetFromBytes(signature);
                continue;
            }

            FindOffsetFromJumpTable(signature);
        }
    }

    private void FindOffsetFromBytes(SignatureInfo signature)
    {
        var results = _scanner.FindPattern(signature.Signature);
        if (results.Count == 0)
        {
            Console.WriteLine($"[x] Faile to find signature for {signature.Name}");
            return;
        }

        foreach (var result in results)
            switch (signature.ReadType)
            {
                case ReadType.None:
                    break;
                case ReadType.Uint8:
                {
                    Console.WriteLine($"[+] {signature.Name}: 0x{_scanner.ReadByte((int)result + signature.Offset):X}");
                    break;
                }
                case ReadType.Uint16:
                {
                    Console.WriteLine($"[+] {signature.Name}: 0x{_scanner.ReadUInt16((int)result + signature.Offset):X}");
                    break;
                }
                case ReadType.Uint32:
                {
                    Console.WriteLine($"[+] {signature.Name}: 0x{_scanner.ReadUInt32((int)result + signature.Offset):X}");
                    break;
                }
                case ReadType.Uint64:
                {
                    Console.WriteLine($"[+] {signature.Name}: 0x{_scanner.ReadUInt64((int)result + signature.Offset):X}");
                    break;
                }
                default:
                {
                    Console.WriteLine($"[x] {signature.Name} has invalid ReadType.");
                    break;
                }
            }
    }

    private void FindOffsetFromJumpTable(SignatureInfo signature)
    {
        var results = _scanner.FindPattern(signature.Signature);
        switch (results.Count)
        {
            case 0:
                Console.WriteLine($"[x] Signature for {signature.Name} has no result. Please update the signature.");
                return;
            case > 1:
                Console.WriteLine($"[x] Signature for {signature.Name} has more than 1 result. Please update the signature to make sure it is unique.");
                return;
        }

        Console.WriteLine($"\n[-] Finding OpCodes from {signature.Name}");

        var address = results[0];

        var bytes = _scanner.ReadBytes((int)address, signature.FunctionSize);
        var codeReader = new ByteArrayCodeReader(bytes);
        var decoder = Decoder.Create(64, codeReader);
        decoder.IP = address;
        var tableInfos = new List<TableInfo>();

        ProcessJumpTable(signature, codeReader, decoder, ref tableInfos);

        FindOpcodeFromJumpTable(signature, tableInfos);
    }

    private void ProcessJumpTable(SignatureInfo signature, ByteArrayCodeReader codeReader, Decoder decoder, ref List<TableInfo> tableInfos)
    {
        var subs = new List<int>();
        var indirectTables = new List<ulong>();
        var jumpTables = new List<ulong>();

        while (codeReader.CanReadByte)
        {
            decoder.Decode(out var instr);

            var instrString = instr.ToString();

            if (instrString.StartsWith("sub eax,"))
            {
                var subValue = instrString.Substring(instrString.IndexOf(',') + 1).Replace("h", "");
                subs.Add(int.Parse(subValue, NumberStyles.HexNumber));
                continue;
            }

            if (instrString.StartsWith("lea eax,["))
            {
                var number = instrString.Substring(instrString.LastIndexOf('-') + 1).Replace("]", "").Replace("h", "");
                subs.Add(int.Parse(number, NumberStyles.HexNumber));
                continue;
            }

            if (instrString.StartsWith("movzx eax,byte ptr [rdx+rax+"))
            {
                indirectTables.Add(instr.NearBranch64 - MagicOffset);
                continue;
            }

            if (instrString.StartsWith("mov ecx,[") && instrString.Contains("+rax*4+")) jumpTables.Add(instr.NearBranch64 - MagicOffset);
        }

        if (jumpTables.Count == 0)
        {
            Console.WriteLine($"[x] No jumptable was found for {signature.Name}.");
            return;
        }

        if (signature.JumpTableType == JumpTableType.Indirect && indirectTables.Count != jumpTables.Count)
        {
            Console.WriteLine($"[x] The size of indirect table doesn't match to jump table. Function: {signature.Name}");
            return;
        }

        var startIndex = signature.JumpTableType == JumpTableType.Indirect ? 1 : 0;

        for (var i = startIndex; i < jumpTables.Count; i++)
        {
            var idx = signature.JumpTableType == JumpTableType.Indirect ? i - 1 : i;

            var minimumCaseValue = subs[idx];
            var jumpTable = jumpTables[idx];

            switch (signature.JumpTableType)
            {
                case JumpTableType.Indirect:
                {
                    var indirectTable = indirectTables[idx];
                    var delta = jumpTables[i] - indirectTable;

                    for (var j = minimumCaseValue; j < minimumCaseValue + (int)delta; j++)
                    {
                        var jumpTableIndex = j - minimumCaseValue;
                        var tableByte = _arrayData[(int)indirectTable + jumpTableIndex];

                        var location = BitConverter.ToInt32(_arrayData, (int)jumpTable + tableByte * 4) - MagicOffset;

                        tableInfos.Add(new TableInfo
                                       {
                                           Index = j,
                                           Location = (ulong)location
                                       });
                    }

                    break;
                }
                case JumpTableType.Direct:
                {
                    for (var j = minimumCaseValue;; j++)
                    {
                        var jumpTableIndex = j - minimumCaseValue;
                        var tableAddress = (int)jumpTable + jumpTableIndex * 4;
                        var tableByte1 = _arrayData[tableAddress];
                        var tableByte2 = _arrayData[tableAddress + 1];
                        if (tableByte1 == 0xCC && tableByte2 == 0xCC)
                            break;

                        var location = BitConverter.ToInt32(_arrayData, tableAddress) - MagicOffset;
                        tableInfos.Add(new TableInfo
                                       {
                                           Index = j,
                                           Location = (ulong)location
                                       });
                        // Console.WriteLine($"DirectTable#{jumpTableIndex}({j}) 0x{location:X}");
                    }

                    break;
                }
            }
        }
    }

    private void FindOpcodeFromJumpTable(SignatureInfo signature, List<TableInfo> tableInfos)
    {
        foreach (var subSignature in signature.SubInfo)
        {
            var results = _scanner.FindPattern(subSignature.Signature);

            switch (subSignature.ActionType)
            {
                case ActionType.None:
                {
                    var skip = false;
                    for (var offset = 0; offset <= 0x30; offset++)
                    {
                        var filteredResults = results.SelectMany(result => tableInfos.Where(info => info.Location == result - (ulong)offset));
                        if (!filteredResults.Any())
                            continue;
                        Console.WriteLine($"[+] {(filteredResults.Count() > 1 ? "Possible opcodes for " : "")}{subSignature.Name}: {filteredResults.Aggregate("", (current, info) => current + $"0x{info.Index:X} ")}");
                        skip = true;
                        break;
                    }

                    if (!skip)
                        Console.WriteLine($"[x] Cannot find opcode for {subSignature.Name}");

                    continue;
                }
                case ActionType.ReadThenCrossReference:
                {
                    // Read value first
                    foreach (var result in results)
                    {
                        ulong value = 0;
                        switch (subSignature.ReadType)
                        {
                            case ReadType.None:
                                break;
                            case ReadType.Uint8:
                            {
                                value = _arrayData[(int)result + subSignature.Offset];
                                break;
                            }
                            case ReadType.Uint16:
                            {
                                value = BitConverter.ToUInt16(_arrayData, (int)result + subSignature.Offset);
                                break;
                            }
                            case ReadType.Uint32:
                            {
                                value = BitConverter.ToUInt32(_arrayData, (int)result + subSignature.Offset);
                                break;
                            }
                            case ReadType.Uint64:
                            {
                                value = BitConverter.ToUInt64(_arrayData, (int)result + subSignature.Offset);
                                break;
                            }
                            default:
                            {
                                Console.WriteLine($"[x] {subSignature.Name} has invalid ReadType.");
                                break;
                            }
                        }

                        var name = "";

                        if (subSignature.DesiredValues != null && subSignature.DesiredValues.TryGetValue((int)value, out var v))
                            name = v;

                        // Finding the start of the function
                        var functionStart = result;
                        for (var i = 0; i <= 0x50; i++)
                        {
                            if (_arrayData[functionStart - (ulong)i] != 0xCC)
                                continue;
                            functionStart -= (ulong)(i - 1);
                            break;
                        }

                        // Finding References
                        var xrefResults = new List<TableInfo>();
                        var xrefs = _scanner.GetCrossReference((int)functionStart);
                        foreach (var xref in xrefs)
                            for (var offset = 0; offset <= 0x30; offset++)
                            {
                                var curAddress = xref - (ulong)offset;
                                var info = tableInfos.Find(i => i.Location == curAddress);
                                if (info.Index == 0)
                                    continue;

                                xrefResults.Add(info);
                                break;
                            }

                        Console.WriteLine($"[+] {subSignature.Name}{name}: {xrefResults.Aggregate("", (current, xrefResult) => current + $"0x{xrefResult.Index:X} ")}");
                    }

                    break;
                }
                case ActionType.CrossReference:
                {
                    var xrefResults = new List<TableInfo>();
                    if (subSignature.ReferenceCount != null)
                    {
                        if (results.Count > 1)
                        {
                            Console.WriteLine($"[x] The signature for {subSignature.Name} has multiple results while ReferenceCount is not empty");
                            continue;
                        }

                        var xrefs = _scanner.GetCrossReference((int)results[0], (int)subSignature.ReferenceCount);
                        if (xrefs == 0)
                        {
                            Console.WriteLine($"[x] No references was found for {subSignature.Name}");
                            continue;
                        }

                        foreach (var address in offsetList.Select(i => xrefs + (ulong)i))
                        {
                            for (var offset = 0; offset <= 0x30; offset++)
                            {
                                var curAddress = address - (ulong)offset;
                                var info = tableInfos.Find(i => i.Location == curAddress);
                                if (info.Index == 0)
                                    continue;

                                xrefResults.Add(info);
                                break;
                            }

                            if (xrefResults.Count != 0)
                                break;
                        }

                        if (xrefResults.Count == 0)
                        {
                            Console.WriteLine($"[x] Cannot find opcode for {subSignature.Name}. Signature result count: {results.Count} / 0x{results[0]:X}");
                            continue;
                        }

                        Console.WriteLine($"[+] {subSignature.Name}: {xrefResults.Aggregate("", (current, xrefResult) => current + $"0x{xrefResult.Index:X} ")}");

                        continue;
                    }

                    foreach (var offsetedXRef in from magicOffset in offsetList
                                                 from result in results
                                                 let xrefs = _scanner.GetCrossReference((int)result)
                                                 from xref in xrefs
                                                 select xref + (ulong)magicOffset)
                    {
                        for (var offset = 0; offset <= 0x30; offset++)
                        {
                            var curAddress = offsetedXRef - (ulong)offset;
                            var info = tableInfos.Find(i => i.Location == curAddress);
                            if (info.Index == 0)
                                continue;

                            xrefResults.Add(info);
                            break;
                        }

                        if (xrefResults.Count != 0)
                            break;
                    }

                    if (xrefResults.Count == 0)
                    {
                        Console.WriteLine($"[x] Cannot find opcode for {subSignature.Name}. Signature result count: {results.Count} / 0x{results[0]:X}");
                        continue;
                    }

                    Console.WriteLine($"[+] {subSignature.Name}: {xrefResults.Aggregate("", (current, xrefResult) => current + $"0x{xrefResult.Index:X} ")}");

                    break;
                }
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }

    private struct TableInfo
    {
        public int Index;
        public ulong Location;
    }
}