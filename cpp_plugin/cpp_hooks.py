import logging
import ida_frame
import ida_funcs
import ida_idp
import ida_struct
import ida_xref
import idautils
import ida_typeinf
import idaapi
import idc
import ida_hexrays

import utils
from utils import batchmode

log = logging.getLogger("ida_medigate")


"""
IDA7.0 bugs

ida_struct.get_member_by_id()  @return: tuple(mptr, member_fullname, sptr)
    IDA7.0:
        sptr points to some wrong struct. Attempts to access this struct lead to IDA crash
    In IDA7.5 SP3:
        sptr points to a proper struct

IDB_Hooks
    Function renamed:
        IDA7.0:
            renamed
        IDA7.5 SP3:
            renamed

    Function type changed (Y on the whole function):
        IDA7.0:
            ti_changed
            func_udpated
            for each arg in function frame:
                renaming_struc_member
                renamed
        IDA7.5 SP3:
            (the same)

    Function arg renamed or type changed (Y on the function arg):
        IDA7.0:
            ti_changed (function)
            func_udpated
        IDA7.5 SP3:
            (the same)
            + sometimes (unpredictable) there might also be the following events:
                ti_changed (arg)
                renaming_struc_member (arg)
                renamed (arg)

    Structure member renamed:
        IDA7.0:
            renaming_struc_member
            renamed (only happens if name was successfully set)
        IDA7.5 SP3:
            (the same)

    Structure member type changed:
        IDA7.0:
            struct_member_changed (member tinfo = OLD type!) (seems like a bug in IDA7.0)
            ti_changed (member tinfo = NEW type)
        IDA7.5 SP3:
            ti_changed (member tinfo = NEW type)
            struct_member_changed (member tinfo = NEW type)
"""


@batchmode
def post_func_name_change(new_name, ea):
    xrefs = idautils.XrefsTo(ea, ida_xref.XREF_USER)
    xrefs = [xref for xref in xrefs if xref.type == ida_xref.dr_I and xref.user == 1]
    args_list = []
    for xref in xrefs:
        res = ida_struct.get_member_by_id(xref.frm)
        if not res or not res[0]:
            log.warning("Xref from %08X wasn't struct_member", xref.frm)
            continue
        # In IDA7.0 get_member_by_id() returns incorrect struct, which,
        # when accessed, causes IDA to crash.
        # In IDA7.5 SP3 get_member_by_id() returns correct struct.
        # So it looks like an IDA bug.
        # To avoid crashes, we get struct from the member's full name.
        # This approach works both in IDA7.0 and IDA7.5 SP3
        member = res[0]
        struct = ida_struct.get_member_struc(ida_struct.get_member_fullname(member.id))
        assert struct
        args_list.append([struct, member.get_soff(), new_name])

    return utils.set_member_name, args_list


def post_struct_member_name_change(member, new_name):
    xrefs = idautils.XrefsFrom(member.id)
    xrefs = [xref for xref in xrefs if xref.type == ida_xref.dr_I and xref.user == 1]
    for xref in xrefs:
        if utils.is_func_start(xref.to):
            utils.set_func_name(xref.to, new_name)


def post_struct_member_type_change(member):
    xrefs = idautils.XrefsFrom(member.id)
    xrefs = [xref for xref in xrefs if xref.type == ida_xref.dr_I and xref.user == 1]
    for xref in xrefs:
        if utils.is_func_start(xref.to):
            member_tinfo = idaapi.tinfo_t()
            ida_struct.get_member_tinfo(member_tinfo, member)
            if member_tinfo.is_funcptr():
                function_tinfo = member_tinfo.get_pointed_object()
                if function_tinfo:
                    if not ida_typeinf.apply_tinfo(xref.to, function_tinfo, idaapi.TINFO_DEFINITE):
                        log.warn(
                            "Failed to apply tinfo %s -> %s",
                            ida_struct.get_member_fullname(member.id),
                            idc.get_name(xref.to),
                        )


@batchmode
def post_func_type_change(funcea):
    xrefs = idautils.XrefsTo(funcea, ida_xref.XREF_USER)
    xrefs = [xref for xref in xrefs if xref.type == ida_xref.dr_I and xref.user == 1]
    args_list = []
    if not xrefs:
        return None, []
    try:
        xfunc = ida_hexrays.decompile(funcea)
        func_ptr_typeinf = utils.get_typeinf_ptr(xfunc.type)
        for xref in xrefs:
            res = ida_struct.get_member_by_id(xref.frm)
            if not res or not res[0]:
                log.warning("Can't get struct for member %08X", xref.frm)
                continue
            member = res[0]
            struct = ida_struct.get_member_struc(ida_struct.get_member_fullname(member.id))
            assert struct
            args_list.append([struct, member, 0, func_ptr_typeinf, idaapi.TINFO_DEFINITE])
    except ida_hexrays.DecompilationFailure:
        # TODO: get func type even if decompilation fails
        pass
    return ida_struct.set_member_tinfo, args_list


class CPPHooks(ida_idp.IDB_Hooks):
    def __init__(self, is_decompiler_on):
        super(CPPHooks, self).__init__()
        self.is_decompiler_on = is_decompiler_on

    def renamed(self, ea, new_name, local_name):
        # Called both for func and field renames AFTER name was successfully set
        if utils.is_func_start(ea):
            func, args_list = post_func_name_change(new_name, ea)
            self.unhook()
            for args in args_list:
                func(*args)
            self.hook()
        return 0

    def func_updated(self, pfn):
        # This only called when user updates func type (weather it actually updated or not, doesn't matter)
        # It is not called when function is renamed, both in IDA7.0 and 7.5
        funcea = pfn.start_ea
        func, args_list = post_func_type_change(funcea)
        self.unhook()
        for args in args_list:
            func(*args)
        self.hook()
        return 0

    def renaming_struc_member(self, sptr, mptr, newname):
        if sptr.is_frame():
            return 0
        # FIXME: should not post here, because the name might be bad and never actually change
        # For example if such name already exists, this hook will be called, then error about
        # duplicate name will be shown, and name will not be actually changed
        # TODO: move to renamed
        post_struct_member_name_change(mptr, newname)
        return 0

    def struc_member_changed(self, sptr, mptr):
        # FIXME: due to the bug in IDA7.0 the actual type of mptr has not changed yet, when this hook is being called
        # TODO: move to ti_changed
        post_struct_member_type_change(mptr)
        return 0

    def ti_changed(self, ea, type, fnames):
        if self.is_decompiler_on:
            res = ida_struct.get_member_by_id(ea)
            if res and res[0]:
                member = res[0]
                struct = ida_struct.get_member_struc(ida_struct.get_member_fullname(member.id))
                assert struct
                if struct.is_frame():
                    # func_updated does not get called if you rename single arg in decompiler,
                    # so we need to call it manually here
                    func = ida_funcs.get_func(ida_frame.get_func_by_frame(struct.id))
                    if not func:
                        log.warning("Couldn't get func by frame 0x%X", struct.id)
                        return 0
                    return self.func_updated(func)
            elif utils.is_func_start(ea):
                # FIXME: no need to call it manually, IDA will do it herself
                return self.func_updated(ida_funcs.get_func(ea))
        return 0
