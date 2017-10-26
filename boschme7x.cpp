/*
 *  This is a sample plugin module
 *
 *  It can be compiled by any of the supported compilers:
 *
 *      - Borland C++, CBuilder, free C++
 *      - Watcom C++ for DOS32
 *      - Watcom C++ for OS/2
 *      - Visual C++
 *
 */

//Standard Defs
typedef int     BOOL;
#define FALSE   0
#define TRUE    1
#define NULL    0
#define TOOLVERSION 1.6
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include <name.hpp>
//#pragma warning( disable:4273 )
#include <bytes.hpp>
#include <kernwin.hpp>
#include "BoschHelper.h"

extern plugin_t PLUGIN;

BoschHelper	myBoshHelper; //our class

//--------------------------------------------------------------------------
// Example of a user-defined IDC function in C++

static const char myBoschME7xfunc5_args[] = { VT_LONG, VT_STR, 0 };
static error_t idaapi myfunc5(value_t *argv, value_t *res)
{
	msg("myBoschME7xfunc is called with arg0=%x and arg1=%s\n", argv[0].num, argv[1].str);
  res->num = 5;     // let's return 5
  return eOk;
}

static int idaapi BoschME7x_callback(void * /*user_data*/, int event_id, va_list /*va*/)
{
  if ( event_id != ui_msg )     // avoid recursion
    if ( event_id != ui_obsolete_setstate
      && event_id != ui_obsolete_showauto
      && event_id != ui_refreshmarked ) // ignore uninteresting events
                    msg("ui_callback %d\n", event_id);
  return 0;                     // 0 means "process the event"
                                // otherwise the event would be ignored
}

//--------------------------------------------------------------------------
// A sample how to generate user-defined line prefixes
//
/*
static const int prefix_width = 8;

static void get_user_defined_prefix(ea_t ea,
                                    int lnnum,
                                    int indent,
                                    const char *line,
                                    char *buf,
                                    size_t bufsize)
{
  buf[0] = '\0';        // empty prefix by default

  // We want to display the prefix only the lines which
  // contain the instruction itself

  if ( indent != -1 ) return;           // a directive
  if ( line[0] == '\0' ) return;        // empty line
  if ( tag_advance(line,1)[-1] == ash.cmnt[0] ) return; // comment line...

  // We don't want the prefix to be printed again for other lines of the
  // same instruction/data. For that we remember the line number
  // and compare it before generating the prefix

  static ea_t old_ea = BADADDR;
  static int old_lnnum;
  if ( old_ea == ea && old_lnnum == lnnum ) return;

  // Ok, seems that we found an instruction line.

  // Let's display the size of the current item as the user-defined prefix
  ulong our_size = get_item_size(ea);

  // We don't bother about the width of the prefix
  // because it will be padded with spaces by the kernel

  qsnprintf(buf, bufsize, " %d", our_size);

  // Remember the address and line number we produced the line prefix for:
  old_ea = ea;
  old_lnnum = lnnum;

}
*/
//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void)
{
  if ( inf.filetype == f_ELF ) return PLUGIN_SKIP;

// Please uncomment the following line to see how the notification works
//  hook_to_notification_point(HT_UI, sample_callback, NULL);
//  PLUGIN.flags &= ~PLUGIN_UNL;

// Please uncomment the following line to see how to the user-defined prefix works
//  set_user_defined_prefix(prefix_width, get_user_defined_prefix);

// Please uncomment the following line to see how to define IDC functions
//  set_idc_func("MyBoschME7xFunc5", myfunc5, myfunc5_args);

  const char *options = get_plugin_options("BoschME7x");
  if ( options != NULL )
    warning("command line options: %s", options);

  return (PLUGIN.flags & PLUGIN_UNL) ? PLUGIN_OK : PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void)
{
  unhook_from_notification_point(HT_UI, BoschME7x_callback);
  set_user_defined_prefix(0, NULL);
  set_idc_func_ex("MyBoschME7xFunc5", NULL, NULL, NULL);  
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user selects the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

void idaapi run(int arg)
{
	unsigned short BOSCH = 0x01;
	char const ME7VERSION[MAXSTR] = "1.6";
	unsigned short defSegs = 0x01;
	unsigned short DissAsm = 0x02;
	unsigned short findSandFuncs =0x04;
	unsigned short findDTC =0x08;
	unsigned short createOffsets=0x10;
	unsigned short cfg_box_2_answer=0x00;
	unsigned short loadASAP=0x20;
	//char label[MAXSTR] = "";
		

	static const char cfg_box_2 []=
		"Bosch ME7 tool version 1.6\n"
		"v1.3 - fix for IDA SDK 6.8 and simple function names. Works with IDA 6.8 onwards\n"
		"v1.4 - adds new functions detections\n"
		"v1.6 - implement ASAP2 file reading \n"
		"Select your options, click OK, then wait!\n"
		
		"<Define segments? (WARNING - deletes existing disassembly!!!):C>\n"
		"<Disassemble hex to opcodes? :C>\n"
		"<Find standard functions and comment them? (This will take 5 minutes!!):C>\n"
		"<Find DTC flag settings?:C>\n"
		"<Find and create offsets?:C>\n"
		"<Import debug info from ASAP file?:C>>\n";

	if (BOSCH)
	{
		if (! AskUsingForm_c(cfg_box_2, &cfg_box_2_answer) )
	    {
			return;
		}
	}



//  if ( inf.filetype != f_PE ) return PLUGIN_SKIP; // only for PE files
//  ph.id = PLFM_C166
	msg("myBoschME7xfunc - processor is %s, inf.filetype is %d, ph.id is %d\n", inf.procName, inf.filetype, ph.id);
	msg("Last byte  is %x\n", inf.maxEA-1);
	msg("Must create %d segments for code\n", (inf.maxEA-0x800000)/0x10000);
    msg("just fyi: the current screen address is: %a\n", get_screen_ea());
	
	using namespace std;

	if (defSegs & cfg_box_2_answer)
		{
		msg("Calling MakeSegments()\n");
		myBoshHelper.MakeSegments();
		}

	if(findSandFuncs & cfg_box_2_answer)
		{
		msg("Calling SearchForFuncSigsAndThenCmt()\n");
		myBoshHelper.SearchForFuncSigsAndThenCmt();
		}
	
	if(DissAsm & cfg_box_2_answer)
		{
		msg("Calling MakeDissCode()\n");
		myBoshHelper.CreateInterruptVectorTable(); // this clears a lot of nonsense generated automatically too
		myBoshHelper.MakeDissCode();
		
		}
	
	if (findDTC & cfg_box_2_answer)
		{
		msg("Calling SearchForDTCFlagSetting()\n");
		myBoshHelper.SearchForDTCFlagSetting();
		}
	
	if (createOffsets & cfg_box_2_answer)
		{
		msg("Calling SearchForArrayOffsetsAndThenCreate()\n");
		myBoshHelper.SearchForArrayOffsetsAndThenCreate();
		}
	
	if (loadASAP & cfg_box_2_answer)
		{
		msg("Calling loadASAPfile()\n");
		myBoshHelper.loadASAPfile();

	}

	msg("BoschMe7x finished.\n");
}

//--------------------------------------------------------------------------
char comment[] = "BoschME7x %s - Assists in the disassembly of ME7.x ECUs",ME7VERSION;

char help[] =
        "BoschME7x plugin module\n"
        "\n"
        "This module assists the user in disassembling Bosch ME7.x ECUs.\n"
        "\n"
        "It correctly sets up IDA with the ECU addresses and segments. Additionally,\n"
        "it auto disassembles and identifies key routines within the binary.\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "BoschME7x";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-1";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,           // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint
  help,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
