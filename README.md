# IDAProBoschME7
Siemens Bosch ME7.x Disassembler Helper for IDA Pro

This plugin will attempt to remove a lot of manual work when importing a raw Bosch engine management binary into IDA Pro, and then try and disassemble it into meaningful code. It is confined to BoschME7.x versions and will attempt to label functions, structs and vars in line with official Bosch ME7.x Funktionsramhen

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
	



Removed:

	Removed Vauxhall Astra specific code
	
