PROC=boschme7x
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)boschme7x$(O) : $(I)area.hpp $(I)bytes.hpp $(I)expr.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)help.h $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
	          $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp boschme7x.cpp
