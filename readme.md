# FFXIV-OpcodeFinder
This program aims to help finding network opcodes for Final Fantasy XIV.
# Configuration
```js
{
    "GamePath": "path/to/ffxiv_dx11.exe",
    "Signatures": [
        {
            "Signature": "Signature, e.g. 48 89 5C 24 ? 48 89  (Support IDA/olly style)",
            "Name": "C2S_ActionRequest",
            "Offset": 0, // Integer, can be negative
            "FunctionSize": 0, // The size of function, it can be set to INT_MAX, since the program will stop scanning once it detects 0xCC opcode
            "ReadType": 0, // 0-None, 1-Uint8 2-Uint16 3-Uint32 4-Uint64
            "ActionType": 0, // 0-None, 1-ReadThenCrossReference (Read offset first, then check DesiredValue (can be empty), then find the reference), 2-CrossReference
            "ReferenceCount": null, // Can be null, pretty much how many times should the program find the reference calls
            "JumpTableType": 0, // 0-None, 1-DirectJumpTable, 2-IndirectJumpTable
            "DesiredValues": { // Can be null
                "key, Integer": 0,
                // ...
            },
            "SubInfo": [
                // ...
            ]
        }
    ]
}
```