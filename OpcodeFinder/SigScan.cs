using System.Globalization;
using System.Runtime.InteropServices;

namespace OpcodeFinder;

internal class RelativeJump
{
    public ulong Destination;
    public ulong Source;
}

internal class SigScanner
{
    private readonly Dictionary<string, SectionInfo> _sectionInfos = new();

    public List<RelativeJump> CallFunctions = new();

    public SigScanner(byte[] buffer)
    {
        ArrayData = buffer;

        unsafe
        {
            fixed (byte* p = buffer)
            {
                var ptr = (IntPtr)p;

                // We don't want to read all of IMAGE_DOS_HEADER or IMAGE_NT_HEADER stuff so we cheat here.
                var ntNewOffset = Marshal.ReadInt32(ptr, 0x3C);
                var ntHeader = ptr + ntNewOffset;

                // IMAGE_NT_HEADER
                var fileHeader = ntHeader + 4;
                var numSections = Marshal.ReadInt16(ntHeader, 6);

                // IMAGE_OPTIONAL_HEADER
                var optionalHeader = fileHeader + 20;

                var sectionHeader = optionalHeader + 240;

                var sectionCursor = sectionHeader;
                for (var i = 0; i < numSections; i++)
                {
                    var sectionName = Marshal.ReadInt64(sectionCursor);

                    // .text
                    switch (sectionName)
                    {
                        case 0x747865742E: // .text
                            _sectionInfos.Add(".text", new SectionInfo
                                                       {
                                                           Offset = Marshal.ReadInt32(sectionCursor, 12),
                                                           Size = Marshal.ReadInt32(sectionCursor, 8)
                                                       });
                            break;
                        case 0x617461642E: // .data
                            _sectionInfos.Add(".data", new SectionInfo
                                                       {
                                                           Offset = Marshal.ReadInt32(sectionCursor, 12),
                                                           Size = Marshal.ReadInt32(sectionCursor, 8)
                                                       });
                            break;
                        case 0x61746164722E: // .rdata
                            _sectionInfos.Add(".rdata", new SectionInfo
                                                        {
                                                            Offset = Marshal.ReadInt32(sectionCursor, 12),
                                                            Size = Marshal.ReadInt32(sectionCursor, 8)
                                                        });
                            break;
                    }

                    sectionCursor += 40;
                }
            }
        }
    }

    private byte[] ArrayData { get; }

    public byte ReadByte(int index)
    {
        return ArrayData[index];
    }

    public byte[] ReadBytes(int offset, int size)
    {
        var data = new byte[size];
        Array.Copy(ArrayData, offset, data, 0, size);
        return data;
    }

    public ushort ReadUInt16(int offset)
    {
        return BitConverter.ToUInt16(ArrayData, offset);
    }

    public uint ReadUInt32(int offset)
    {
        return BitConverter.ToUInt32(ArrayData, offset);
    }

    public ulong ReadUInt64(int offset)
    {
        return BitConverter.ToUInt64(ArrayData, offset);
    }

    public List<ulong> FindPattern(string szPattern)
    {
        if (ArrayData == null)
            throw new Exception("ArrayData is emptry");

        var results = Find(ArrayData, 0, ArrayData.Length, HexToBytes(szPattern));

        return results;
    }

    public List<ulong> GetCrossReference(int offset)
    {
        if (!_sectionInfos.TryGetValue(".text", out var info))
            throw new DirectoryNotFoundException("Cannot find section .text");

        if (CallFunctions.Count == 0)
        {
            var e8 = Find(ArrayData, info.Offset, info.Size, HexToBytes("E8 ? ? ? ?"));
            foreach (var relatives in e8)
                CallFunctions.Add(new RelativeJump
                                  {
                                      Source = relatives,
                                      Destination = (ulong)ReadCallSig((int)relatives)
                                  });

            var e9 = Find(ArrayData, info.Offset, info.Size, HexToBytes("E9 ? ? ? ?"));
            foreach (var relatives in e9)
                CallFunctions.Add(new RelativeJump
                                  {
                                      Source = relatives,
                                      Destination = (ulong)ReadCallSig((int)relatives)
                                  });
        }

        return CallFunctions.Where(i => i.Destination == (ulong)offset).Select(i => i.Source).ToList();
    }

    public ulong GetCrossReference(int offset, int count)
    {
        ulong functionStart = 0;

        count = Math.Max(count, 1);

        for (var i = 0; i < count; i++)
        {
            var xrefs = GetCrossReference(i == 0 ? offset : (int)functionStart);
            var curAddr = xrefs[0];
            if (i != count - 1)
                for (var j = 0; j <= 0x50; j++)
                {
                    if (ArrayData[curAddr - (ulong)j] != 0xCC)
                        continue;
                    curAddr -= (ulong)(j - 1);
                    functionStart = curAddr;
                    break;
                }
            else
                functionStart = curAddr;
        }

        return functionStart;
    }

    public int ReadCallSig(int offset)
    {
        var jumpOffset = BitConverter.ToInt32(ArrayData, offset + 1);
        return offset + jumpOffset + 5;
    }

    private static List<ulong> Find(IReadOnlyList<byte> data, int start, int size, IReadOnlyList<int> pattern)
    {
        var results = new List<ulong>();
        for (var nModuleIndex = start; nModuleIndex < size; nModuleIndex++)
        {
            if (data[nModuleIndex] != pattern[0])
                continue;

            if (ByteMatch(data, nModuleIndex, pattern))
                results.Add((ulong)nModuleIndex);
        }

        return results;
    }

    public static bool ByteMatch(IReadOnlyList<byte> bytes, int start, IReadOnlyList<int> pattern)
    {
        for (int i = start, j = 0; j < pattern.Count; i++, j++)
        {
            if (pattern[j] == -1)
                continue;

            if (bytes[i] != pattern[j])
                return false;
        }

        return true;
    }

    public static List<int> HexToBytes(string hex)
    {
        var bytes = new List<int>();

        for (var i = 0; i < hex.Length - 1;)
        {
            switch (hex[i])
            {
                case '?':
                {
                    if (hex[i + 1] == '?')
                        i++;
                    i++;
                    bytes.Add(-1);
                    continue;
                }
                case ' ':
                    i++;
                    continue;
            }

            var byteString = hex.Substring(i, 2);
            var b = byte.Parse(byteString, NumberStyles.AllowHexSpecifier);
            bytes.Add(b);
            i += 2;
        }

        return bytes;
    }

    private struct SectionInfo
    {
        public int Offset;
        public int Size;
    }
}