#!/usr/bin/python
# -*- coding: utf-8 -*-
import idautils
import idaapi
import idc
import ida_search
import ida_ida
import ida_bytes
import ida_idaapi

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = 'IDA Offset/Reference Finder by vesko_hard'
    help = 'This is help'
    wanted_name = 'IDA_Finder plugin '
    wanted_hotkey = 'F10'

    def init(self):
        return idaapi.PLUGIN_OK

    def _generate_pattern(self, addr, is_be):
        a4, a3, a2, a1 = (addr >> 24 & 0xFF, addr >> 16 & 0xFF, addr >> 8 & 0xFF, addr & 0xFF)
        if is_be:
            bin_str = f"{a4:02X} {a3:02X} {a2:02X} {a1:02X}"
        else:
            bin_str = f"{a1:02X} {a2:02X} {a3:02X} {a4:02X}"
        return bin_str

    def _search_pattern(self, bin_str, is_be):
        idaapi.msg(f"Searching for: {bin_str}, endian: {'BE' if is_be else 'LE'}\n")
        adr = ida_ida.inf_get_min_ea()
        match_count = 0

        while True:
            adr = ida_bytes.find_bytes(bin_str, adr, radix=16)
            if adr == ida_idaapi.BADADDR:
                break

            idaapi.msg(f"Found offset {adr:08X}\n")
            match_count += 1
            adr += 1  # Move to the next search position

        if match_count == 0:
            idaapi.msg(f"Data not found [{bin_str}]\n")
        else:
            idaapi.msg(f"Data found {match_count} times.\n")

    def run(self, arg):
        is_be = ida_ida.inf_is_be()
        addr = idc.get_screen_ea()

        idaapi.msg(f"ENDIAN: {'BE' if is_be else 'LE'}\n")

        # Search normal pattern
        bin_str = self._generate_pattern(addr, is_be)
        self._search_pattern(bin_str, is_be)

        # If processor is ARM, adjust address and search again
        if idc.get_processor_name().startswith("ARM"):
            idaapi.msg("ARM detected, searching adjusted address...\n")
            addr += 1
            bin_str = self._generate_pattern(addr, is_be)
            self._search_pattern(bin_str, is_be)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return myplugin_t()
