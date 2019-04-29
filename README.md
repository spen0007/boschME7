# IDAProBoschME7
Siemens Bosch ME7.x Disassembler Helper for IDA Pro
<br>
This is Andy Whittaker's code updated as follows:

	Update for compile with Visual C++ 2008 onwards
	Update for compiling against IDA SDK 6.8 onwards

This will not run against earlier versions of ida.  I removed deprecated functions calls and replaced them with up to date alternatives, so that this plugin should continue to compile and run for a long time

<br>
Added net new functions:

	ASAP file import
	Decode interrupt Vector Table
	Added more functions definitions
	

This plugin will attempt to remove a lot of manual work from a raw binary and then try and disassemble it into more meaningful code.

Removed:

	Removed Vauxhall Astra specific code
	
