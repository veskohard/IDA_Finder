#!/usr/bin/python
# -*- coding: utf-8 -*-
import idautils
import idaapi
import idc
import ida_search
import ida_ida
import ida_idaapi

class myplugin_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = 'IDA Offset/Reference Finder by vesko_hard'
    help = 'This is help'
    wanted_name = 'IDA_Finder plugin'
    wanted_hotkey = 'F10'

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        is_be = ida_ida.inf_is_be()
        rett = []
        aaa = idc.get_screen_ea()
        s=''
        pattern = idaapi.compiled_binpat_vec_t()

        if is_be:
            s='BE'
            print("ENDIAN: %s" % s)
            a4 = aaa >> 24 & 0xFF
            a3 = aaa >> 16 & 0xFF
            a2 = aaa >> 8 & 0xFF
            a1 = aaa & 0xFF
            bin_str = '%0.2X %0.2X %0.2X %0.2X' % (a4, a3, a2, a1)
            idaapi.parse_binpat_str(pattern,ida_ida.inf_get_min_ea(),bin_str,16,0)
            
        else:
            s='LE'
            print("ENDIAN: %s" % s)
            a4 = aaa >> 24 & 0xFF
            a3 = aaa >> 16 & 0xFF
            a2 = aaa >> 8 & 0xFF
            a1 = aaa & 0xFF
            bin_str = '%0.2X %0.2X %0.2X %0.2X' % (a1, a2, a3, a4)
            idaapi.parse_binpat_str(pattern,ida_ida.inf_get_min_ea(),bin_str,16,0)
        #adr = 0
        adr = idaapi.inf_get_min_ea()
        pat_len = sum(len(pat.bytes) for pat in pattern)
        match=0
        idaapi.msg("Searching for: %s, endian: %s, pattern length: %d\n" % (bin_str,s,pat_len))
        while True:
            adr = idaapi.bin_search(adr,ida_ida.inf_get_max_ea(),pattern,idaapi.BIN_SEARCH_CASE)
            if adr == idaapi.BADADDR:
                break
            if int(adr[0]) > ida_ida.inf_get_max_ea()-pat_len:
                break
            print("Found offset %08X" % (int(adr[0])))
            match += 1
            adr = adr[0] + 1
            
        if match == 0:
            print("data not found [%s]" % bin_str)  
        else: 
            print("data not found %d times" % match)  
          
        
        procesor = idc.get_processor_name()
        if procesor.startswith("ARM"):
            print("ARM")  
            aaa = aaa + 1
            if is_be:
                s='BE'
                print("ENDIAN: %s" % s)
                a4 = aaa >> 24 & 0xFF
                a3 = aaa >> 16 & 0xFF
                a2 = aaa >> 8 & 0xFF
                a1 = aaa & 0xFF
                bin_str = '%0.2X %0.2X %0.2X %0.2X' % (a4, a3, a2, a1)
                idaapi.parse_binpat_str(pattern,ida_ida.inf_get_min_ea(),bin_str,16,0)
            
            else:
                s='LE'
                print("ENDIAN: %s" % s)
                a4 = aaa >> 24 & 0xFF
                a3 = aaa >> 16 & 0xFF
                a2 = aaa >> 8 & 0xFF
                a1 = aaa & 0xFF
                bin_str = '%0.2X %0.2X %0.2X %0.2X' % (a1, a2, a3, a4)
                idaapi.parse_binpat_str(pattern,ida_ida.inf_get_min_ea(),bin_str,16,0)
        
            adr = idaapi.inf_get_min_ea()
            pat_len = sum(len(pat.bytes) for pat in pattern)
            match=0
            idaapi.msg("Searching for: %s, endian: %s, pattern length: %d\n" % (bin_str,s,pat_len))
            while True:
                adr = idaapi.bin_search(adr,ida_ida.inf_get_max_ea(),pattern,idaapi.BIN_SEARCH_CASE)
                if adr == idaapi.BADADDR:
                    break
                if int(adr[0]) > ida_ida.inf_get_max_ea()-pat_len:
                    break
                print("Found ARM call %08X" % (int(adr[0])))
                match += 1
                adr = adr[0] + 1
                
            if match == 0:
                print("data not found [%s]" % bin_str)  
            else: 
                print("data not found %d times" % match)  
            

    def term(self):
        pass


def PLUGIN_ENTRY():
    return myplugin_t()
