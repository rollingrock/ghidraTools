# ghidraTools

Collection of utility scripts for ghidra for Bethesda game reverse engineering.

- idaXMLSymbols (Python) - Converts ida dump xml symbols to the x64dbg format that is [easily imported into ghidra](https://github.com/alxbl/x64dbg-ghidra). builds the dd64 file format by parsing these lines in the xml

```xml
<SYMBOL ADDRESS="0x140001000" NAME="_lambda_3763db3ea44bebb6b5a5ba80abe5d030_::_lambda_3763db3ea44bebb6b5a5ba80abe5d030_" />
```

- PopulateParameters (Java) - Populate parameters based on symbol names. This script will try to populate parameters in a function for 1) class parameters based on namespace detection (e.g., ("class::function") and 2) any parameter definition in the name (e.g., "funcname(param_type1, paramtype_2)()"). Only valid datatypes within the program will be populated. Any arguments will be renamed with the missing datatype name.
