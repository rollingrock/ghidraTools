# ghidraTools

Collection of utility scripts for ghidra for Bethesda game reverse engineering.

- idaXMLSymbols (Python) - Converts ida dump xml symbols to the x64dbg format that is [easily imported into ghidra](https://github.com/alxbl/x64dbg-ghidra). builds the dd64 file format by parsing these lines in the xml

```xml
<SYMBOL ADDRESS="0x140001000" NAME="_lambda_3763db3ea44bebb6b5a5ba80abe5d030_::_lambda_3763db3ea44bebb6b5a5ba80abe5d030_" />
```

- PopulateParameters (Java) - Populate parameters based on symbol names. This script will try to populate parameters in a function for 1) class parameters based on namespace detection (e.g., ("class::function") and 2) any parameter definition in the name (e.g., "funcname(param_type1, paramtype_2)()"). Only valid datatypes within the program will be populated. Any arguments will be renamed with the missing datatype name.

- FindBethesdaVariablesScript (Java) - This script will search for data types that follow Bethesda Settings Variables rules and rename them accordingly. Found in Skyrim/Fallout/Starfall. These are 4 byte data types followed by 4 bytes of 0 and then a string pointer to the data type.

# Links

- https://github.com/Thiago099/ghidra_scripts
- https://github.com/alandtse/pdbgen - Generates fakePDBs using Ghidra data. Used to generate pdbs in [CrashLogger SSE](https://www.nexusmods.com/skyrimspecialedition/mods/59818) and [Buffout4 NG](https://www.nexusmods.com/fallout4/mods/64880)
- [RE Ghidra Wiki](https://github.com/DaymareOn/SSE-Ghidra-Tutorial/wiki)
