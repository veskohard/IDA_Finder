import idautils
import idaapi
import idc
import ida_search

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDA Offset/Reference Finder by vesko_hard"
    help = "This is help"
    wanted_name = "IDA_Finder plugin"
    wanted_hotkey = "F10"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
		if idaapi.cvar.inf.is_be():
			print "is_be = true"
			ea = idc.MinEA()
			aaa = idc.ScreenEA()
			rett = []
			a4 = (aaa >> 24) & 0xFF
			a3 = (aaa >> 16) & 0xFF
			a2 = (aaa >> 8) & 0xFF
			a1 = aaa & 0xFF
			bin_str = "%0.2X %0.2X %0.2X %0.2X" % (a4,a3,a2,a1) 
			while True:
				ea = idc.FindBinary(ea, 1|4, bin_str)
				if ea == idaapi.BADADDR:
					break
				rett.append(ea)
				print "Found BE offset -> 0x%0.8X" % ea
				ea += 1
			if not rett:
				print "BE offset not match [%s]" % bin_str
			ea = idc.MinEA()
			aaa = idc.ScreenEA()
			aaa = aaa + 1
			rett = []
			a4 = (aaa >> 24) & 0xFF
			a3 = (aaa >> 16) & 0xFF
			a2 = (aaa >> 8) & 0xFF
			a1 = aaa & 0xFF
			bin_str = "%0.2X %0.2X %0.2X %0.2X" % (a4,a3,a2,a1) 
			while True:
				ea = idc.FindBinary(ea, 1|4, bin_str)
				if ea == idaapi.BADADDR:
					break
				rett.append(ea)
				print "Found BE call -> 0x%0.8X" % ea
				ea += 1
			if not rett:
				print "BE call not match [%s]" % bin_str
		else:
			print "is_be = false"
			ea = idc.MinEA()
			aaa = idc.ScreenEA()
			ret = []
			a4 = (aaa >> 24) & 0xFF
			a3 = (aaa >> 16) & 0xFF
			a2 = (aaa >> 8) & 0xFF
			a1 = aaa & 0xFF
			bin_str = "%0.2X %0.2X %0.2X %0.2X" % (a1,a2,a3,a4) 
			while True:
				ea = idc.FindBinary(ea, 1|4, bin_str)
				if ea == idaapi.BADADDR:
					break
				ret.append(ea)
				print "Found LE offset -> 0x%0.8X" % ea
				ea += 1
			if not ret:
				print "LE offset not match [%s]" % bin_str
				
			ea = idc.MinEA()
			aaa = idc.ScreenEA()
			rett = []
			aaa = aaa + 1
			a4 = (aaa >> 24) & 0xFF
			a3 = (aaa >> 16) & 0xFF
			a2 = (aaa >> 8) & 0xFF
			a1 = aaa & 0xFF
			bin_str = "%0.2X %0.2X %0.2X %0.2X" % (a1,a2,a3,a4) 
			while True:
				ea = idc.FindBinary(ea, 1|4, bin_str)
				if ea == idaapi.BADADDR:
					break
				rett.append(ea)
				print "Found LE call -> 0x%0.8X" % ea
				ea += 1
			if not rett:
				print "LE call not match [%s]" % bin_str

		
			
		
		
    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()

