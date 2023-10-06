from . import llapi
from unicorn import arm_const
from typing import Union, Tuple
from pathlib import PurePosixPath, PurePath
from traceback import print_exc
import unicorn
import datetime
import time
import os
import platform

EMU_SCREEN_WIDTH = 256
EMU_SCREEN_HEIGHT = 127

def align_up(x, v):
    x += v - 1
    x = x & ~(v - 1)
    return x

def pure_absvpath(vpath: PurePosixPath) -> PurePosixPath:
        vpath = PurePosixPath("/", *vpath.parts)
        parts = list(vpath.parts)
        #flat path
        p = 1 # parts[0] must be "/"
        while p < len(parts):
            name = parts[p]
            if name == "..":
                p -= 1
                if p >= 1:
                    del parts[p]
                    del parts[p]
                else:
                    p = 1
                    del parts[p]
            else:
                p += 1
        return PurePosixPath(*parts)

def virtual_path_to_real_path(rootfs: str, vpath: str):
    abs_path = pure_absvpath(PurePosixPath(vpath))
    rele_path = PurePosixPath(*(abs_path.parts[1:]))
    sys_path = PurePath(rootfs, *rele_path.parts)
    return str(sys_path)

class UIInterface:
    def fill_rect(self, x, y, w, h, c):
        raise NotImplemented()

    def draw_text(self, text, x, y, bg, fg):
        """ draw 8x16 text at position x, y with color bg, fg """
        raise NotImplemented()
    
    def get_pixel(self, x, y) -> int:
        raise NotImplemented()
    
    def is_key_down(self, key_id) -> bool:
        raise NotImplemented()
    
    def query_key_event(self) -> Union[None, Tuple[bool, int]]:
        """ fetch one key event (pressed, key_id), return None if there is no event. """
        raise NotImplemented()
    
    def app_quit(self):
        raise NotImplemented()

class Emulator:
    def __init__(self, ui: UIInterface, rootfs_path: str, exp_file_path: str) -> None: 
        self.ui = ui
        self.rootfs = rootfs_path
        self.exp_file_path = exp_file_path

        self.exp_size = os.stat(self.exp_file_path).st_size
        # print("exp size:%d" % self.exp_size)
    
        self.EXP_ROM_ADDR = 0x08000000
        self.EXP_RAM_ADDR = 0x02080000
        self.EXP_RAM_SZ = 380 * 1024
        self.run = True
        
        self.emu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM926)

        self.emu.mem_map(self.EXP_RAM_ADDR, self.EXP_RAM_SZ, unicorn.UC_PROT_ALL)
        
        #self.emu.mem_map(0, 512*1024, UC_PROT_ALL)
        #self.emu.mem_map(0x02000000, 512*1024, UC_PROT_ALL)

        self.emu.mem_map(self.EXP_ROM_ADDR, align_up(self.exp_size, 4096), unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)

        self.emu.mem_write(self.EXP_ROM_ADDR, open(self.exp_file_path, "rb").read())
        self.emu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self.mem_fault) 
        self.dir_open_list = {}
        self.f_open_list = {}
        self.mmap_list = {}
        self.thread_list = {}
        self.select_thread = 0
        self.tid = 0

    def mem_fault(self, uc: unicorn.unicorn.Uc, access, address, size, value, data):
        retn_addr = self.emu.reg_read(arm_const.UC_ARM_REG_R14)
        pc_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_PC)
        if retn_addr == 0 and pc_ptr == 0:
            # ignore error, it maybe sub thread end.
            return
        print(">>> mem fault address:0x%08X, sz:%d" % (address, size))
        self.dumpreg()
    
    def dumpreg(self):
        for i in range(arm_const.UC_ARM_REG_R0, arm_const.UC_ARM_REG_R12 + 1):
            print("R%d: %08X" % (i-arm_const.UC_ARM_REG_R0, self.emu.reg_read(i)))
        print("R14:%08X" % self.emu.reg_read(arm_const.UC_ARM_REG_R14))
        print("SP:%08X" % self.emu.reg_read(arm_const.UC_ARM_REG_SP))
        print("LR:%08X" % self.emu.reg_read(arm_const.UC_ARM_REG_LR))
        print("PC:%08X" % self.emu.reg_read(arm_const.UC_ARM_REG_PC))
        print("Thread id: %d" % self.select_thread)
    
    def read_str_from_vm(self, vptr):
        c = self.emu.mem_read(vptr, 1)
        strs = bytearray()
        while(c != b'\x00'):
            strs += (c)
            vptr = vptr + 1
            c = self.emu.mem_read(vptr, 1)
        strs = strs.decode("utf-8")
        return strs
    
    def write_str_to_vm(self, s, vptr):
        strs = str(s+"\x00").encode("utf-8")
        self.emu.mem_write(vptr, strs)

    def do_llapi(self):
        swicode = self.emu.mem_read(self.CurPC - 4, 4)
        swicode = int.from_bytes(swicode, byteorder="little", signed=False) & 0xFFFFFF
        ## print(" SWI CODE:%08X" % swicode)
        
        if swicode == llapi.LLAPI_APP_GET_RAM_SIZE:
            # print("Get RAM Sz")
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, self.EXP_RAM_SZ)
            return True
        
        elif swicode == llapi.LLAPI_APP_STDOUT_PUTC:
            c = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            print("%c" % c, end="")
            return True
        
        elif swicode == llapi.LLAPI_APP_GET_TICK_MS:
            ms = int(time.time_ns() / 1_000_000) & 0xFFFFFFFF
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, ms)
            return True
        
        elif swicode == llapi.LLAPI_APP_GET_TICK_US:
            us = int(time.time_ns() / 1_000) & 0xFFFFFFFF
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, us)
            return True
        
        elif swicode == llapi.LLAPI_APP_RTC_GET_S:
            s = int(time.time_ns() / 1_000_000_000) & 0xFFFFFFFF
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, s)
            return True
        
        elif swicode == llapi.LLAPI_APP_EXIT:
            self.ui.app_quit()
            self.run - False
            return True
        
        elif swicode == llapi.LLAPI_SET_PERF_LEVEL:
            _ = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            return True
        
        elif swicode == llapi.LL_SWI_ICACHE_INV:
            return True
        
        elif swicode == llapi.LL_SWI_DCACHE_CLEAN:
            _ = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            _ = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            return True
        
        elif swicode == llapi.LLAPI_APP_DISP_PUT_P:
            x = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            y = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            c = self.emu.reg_read(arm_const.UC_ARM_REG_R2) & 0xFF
            self.ui.fill_rect(x, y, 1, 1, c)
            return True
        
        elif swicode == llapi.LLAPI_APP_DISP_PUT_HLINE:
            y = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            dat = self.emu.mem_read(ptr, 256)
            x = 0
            for b in dat:
                self.ui.fill_rect(x, y, 1, 1, b)
                x += 1
            return True
        
        elif swicode == llapi.LLAPI_APP_DISP_GET_P:
            x = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            y = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, self.ui.get_pixel(x, y))
            return True
        
        elif swicode == llapi.LLAPI_APP_DISP_CLEAN: 
            c = self.emu.reg_read(arm_const.UC_ARM_REG_R0) & 0xFF
            self.ui.fill_rect(0, 0, 256, 127, c)
            return True
        
        elif swicode == llapi.LLAPI_APP_DISP_PUT_KSTRING:
            x = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            y = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            sp = self.emu.reg_read(arm_const.UC_ARM_REG_R2)
            s = self.read_str_from_vm(sp)
            fgbg = self.emu.reg_read(arm_const.UC_ARM_REG_R3)
            bg = fgbg & 0xFF
            fg = (fgbg >> 16) & 0xFF
            self.ui.draw_text(s, x, y, bg, fg)
            return True

        elif swicode == llapi.LLAPI_MMAP:
            mmap_obj = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            mapto = self.emu.mem_read(mmap_obj, 4)
            mapto = int.from_bytes(mapto, byteorder="little", signed=False)
            fpath_addr_bin = self.emu.mem_read(mmap_obj + 4, 4)
            fpath_addr = int.from_bytes(fpath_addr_bin, byteorder="little", signed=False)
            fpath = self.read_str_from_vm(fpath_addr)
            fpath = virtual_path_to_real_path(self.rootfs, fpath)
            offset = self.emu.mem_read(mmap_obj + 8, 4)
            offset = int.from_bytes(offset, byteorder="little", signed=False)
            size = self.emu.mem_read(mmap_obj + 12, 4)
            size = int.from_bytes(size, byteorder="little", signed=False)
            writable = self.emu.mem_read(mmap_obj + 16, 2)
            writeback = self.emu.mem_read(mmap_obj + 18, 2)
            writable = int.from_bytes(writable, byteorder="little", signed=False)
            writeback = int.from_bytes(writeback, byteorder="little", signed=False)
            # print("try mmap:", fpath)
            if os.path.exists(fpath):
                self.mmap_list[mapto] = {}
                if writable:
                    flag = os.O_RDWR
                else:
                    flag = os.O_RDONLY
                if platform.system() == "Windows":
                    flag |= os.O_BINARY
                self.mmap_list[mapto]["fd"] = os.open(fpath, flag)
                self.mmap_list[mapto]["mapto"] = mapto
                self.mmap_list[mapto]["offset"] = offset
                self.mmap_list[mapto]["writeback"] = writeback
                if size == 0:
                    size = os.fstat(self.mmap_list[mapto]["fd"]).st_size
                self.mmap_list[mapto]["size"] = size
                size = align_up(size, 4096)
                # print("Create mmap:to:%08x, path:%s, off:%d, sz:%d, wr:%d, wb:%d" % (mapto, fpath, offset, size, writable, writeback))
                self.emu.mem_map(mapto, size, unicorn.UC_PROT_ALL if writable else unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
                
                os.lseek(self.mmap_list[mapto]["fd"], offset, os.SEEK_SET)
                self.emu.mem_write(mapto, os.read(self.mmap_list[mapto]["fd"], size))
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, mapto)
                return True
            
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
            return True

        elif swicode == llapi.LLAPI_MUNMAP:
            mmap_obj = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if mmap_obj in self.mmap_list:
                if self.mmap_list[mmap_obj]["writeback"] > 0:
                    os.lseek(self.mmap_list[mmap_obj]["fd"], offset, os.SEEK_SET)
                    os.write(self.mmap_list[mmap_obj]["fd"], 
                             self.emu.mem_read(self.mmap_list[mapto]["mapto"], self.mmap_list[mapto]["size"]))
                os.close(self.mmap_list[mmap_obj]["fd"])
                self.emu.mem_unmap(self.mmap_list[mapto]["mapto"])
                self.mmap_list.pop(mmap_obj)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)    
            return True
        
        elif swicode == llapi.LL_SWI_FS_GET_DIROBJ_SZ:
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 1024)
            return True
        
        elif swicode == llapi.LL_SWI_FS_GET_FOBJ_SZ:
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 2048)
            return True
        
        elif swicode == llapi.LL_SWI_FS_OPEN:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr in self.f_open_list:
                self.f_open_list.pop(fobj_ptr)
            path = self.read_str_from_vm(self.emu.reg_read(arm_const.UC_ARM_REG_R1))
            exp_fflag = self.emu.reg_read(arm_const.UC_ARM_REG_R2)
            flag = 0
            
            if exp_fflag & llapi.O_RDONLY:
                flag |= os.O_RDONLY
            if exp_fflag & llapi.O_WRONLY:
                flag |= os.O_WRONLY
            if exp_fflag & llapi.O_TRUNC:
                flag |= os.O_TRUNC
            if exp_fflag & llapi.O_RDWR:
                flag |= os.O_RDWR
            if exp_fflag & llapi.O_APPEND:
                flag |= os.O_APPEND
            if exp_fflag & llapi.O_EXCL:
                flag |= os.O_EXCL
            
            if platform.system() == "Linux":
                if exp_fflag & llapi.O_SYNC:
                    flag |= os.O_SYNC

            if platform.system() == "Windows":
                flag |= os.O_BINARY

            path = virtual_path_to_real_path(self.rootfs, path)
            # print("try open:", path, flag)
            if not os.path.exists(path):
                if exp_fflag & llapi.O_CREAT:
                    flag |= os.O_CREAT
                    # print("create file.")
                else:
                    self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                    return True
            self.f_open_list[fobj_ptr] = {}
            self.f_open_list[fobj_ptr]["path"] = path
            self.f_open_list[fobj_ptr]["fd"] = os.open(path, flag)
            # print("open:", path, self.f_open_list[fobj_ptr]["fd"])
            if(self.f_open_list[fobj_ptr]["fd"]):
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
                # print("FOPEN %s, Successful." % path)
            else:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                # print("FOPEN %s, Failed." % path)
            return True
        
        elif swicode == llapi.LL_SWI_FS_SEEK:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            off = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            whence = self.emu.reg_read(arm_const.UC_ARM_REG_R2)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            ret = os.lseek(self.f_open_list[fobj_ptr]["fd"], off, whence)
            # # print("lseek:%d,%d" % (off, ret))
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, ret)
            return True

        elif swicode == llapi.LL_SWI_FS_WRITE:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            sz = self.emu.reg_read(arm_const.UC_ARM_REG_R2)
            dat = self.emu.mem_read(ptr, sz)
            ret = os.write(self.f_open_list[fobj_ptr]["fd"], dat)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, ret)
            return True
        
        elif swicode == llapi.LL_SWI_FS_READ:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            sz = self.emu.reg_read(arm_const.UC_ARM_REG_R2)
            rdat = os.read(self.f_open_list[fobj_ptr]["fd"], sz)
            self.emu.mem_write(ptr, rdat)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, len(rdat))
            return True

        elif swicode == llapi.LL_SWI_FS_TELL:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, os.lseek(self.f_open_list[fobj_ptr]["fd"], 0, os.SEEK_CUR))
            return True

        elif swicode == llapi.LL_SWI_FS_TRUNCATE:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            length = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            os.truncate(self.f_open_list[fobj_ptr]["fd"], length)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True

        elif swicode == llapi.LL_SWI_FS_SYNC:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            os.fsync(self.f_open_list[fobj_ptr]["fd"])
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True

        elif swicode == llapi.LL_SWI_FS_CLOSE:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr in self.f_open_list:
                os.close(self.f_open_list[fobj_ptr]["fd"])
                # print("CLOSE:", self.f_open_list[fobj_ptr]["path"])
                self.f_open_list.pop(fobj_ptr)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True
        
        elif swicode == llapi.LL_SWI_FS_SIZE:
            fobj_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if fobj_ptr not in self.f_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            sz = os.fstat(self.f_open_list[fobj_ptr]["fd"]).st_size
            # print("Chk sz:%s, %d" % (self.f_open_list[fobj_ptr]["path"], sz))
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, sz) 
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_MKDIR:
            p = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            path = self.read_str_from_vm(p) 
            path = virtual_path_to_real_path(self.rootfs, path)
            # print("MKDIR:", path)
            os.makedirs(path, exist_ok=True) 
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True

        elif swicode == llapi.LL_SWI_FS_DIR_OPEN:
            if self.emu.reg_read(arm_const.UC_ARM_REG_R0) in self.dir_open_list:
                self.dir_open_list.pop(self.emu.reg_read(arm_const.UC_ARM_REG_R0))
            
            path = self.read_str_from_vm(self.emu.reg_read(arm_const.UC_ARM_REG_R1)) 
            path = virtual_path_to_real_path(self.rootfs, path)

            if not os.path.exists(path):
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            if not os.path.isdir(path):
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            try:
                items = len(os.listdir(path))
            except:
                items = 0
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)] = {}
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["path"] = path
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["iter"] = 0
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["total"] = items + 2 # LFS will return '.' and '..' as first 2 entries in a dir.
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["items"] = [".", ".."] + os.listdir(path)
            # print("Open dir:", self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["path"],
            #      self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["total"] )
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_REWIND:
            self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["iter"] = 0
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_TELL:
            pos = self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]["iter"]
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, pos)
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_SEEK:
            d = self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]
            pos = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            if pos < 0 or pos > d["total"]:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            d["iter"] = pos
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_READ:
            if self.emu.reg_read(arm_const.UC_ARM_REG_R0) not in self.dir_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            d = self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]
            if d["iter"] < d["total"]:
                # print(d["items"][d["iter"]])
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, d["total"] - d["iter"])
                d["iter"] += 1
            else:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_GET_CUR_TYPE:
            if self.emu.reg_read(arm_const.UC_ARM_REG_R0) not in self.dir_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            d = self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]
            isdir = os.path.isdir(d["path"] + d["items"][d["iter"] - 1])
            if isdir:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, llapi.FS_FILE_TYPE_DIR)
            else:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, llapi.FS_FILE_TYPE_REG)
            return True

        elif swicode == llapi.LL_SWI_FS_DIR_GET_CUR_NAME:
            dirobj = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            if dirobj not in self.dir_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0) # NULL
                return True
            d = self.dir_open_list[dirobj]
            self.write_str_to_vm(d["items"][d["iter"] - 1], dirobj)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, dirobj)
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_GET_CUR_SIZE:
            if self.emu.reg_read(arm_const.UC_ARM_REG_R0) not in self.dir_open_list:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
                return True
            d = self.dir_open_list[self.emu.reg_read(arm_const.UC_ARM_REG_R0)]
            # print("get sz:", d["path"] + d["items"][d["iter"] - 1])
            isfile = os.path.isfile(d["path"] + d["items"][d["iter"] - 1])
            if(isfile):
                sz = os.stat(d["path"] + d["items"][d["iter"] - 1]).st_size
            else:
                sz = 0
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, sz)
            return True
        
        elif swicode == llapi.LL_SWI_FS_DIR_CLOSE:
            if self.emu.reg_read(arm_const.UC_ARM_REG_R0) in self.dir_open_list:
                self.dir_open_list.pop(self.emu.reg_read(arm_const.UC_ARM_REG_R0))
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 0)
            return True
        
        elif swicode == llapi.LLAPI_APP_QUERY_KEY:
            event = self.ui.query_key_event()
            if event == None:
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, -1)
            else:
                pressed, kval = event
                kval &= 0x7F
                if not pressed:
                    kval |= 1 << 7
                self.emu.reg_write(arm_const.UC_ARM_REG_R0, kval)
            return True
        
        elif swicode == llapi.LLAPI_APP_IS_KEY_DOWN:
            qk = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            self.emu.reg_write(arm_const.UC_ARM_REG_R0, 1 if self.ui.is_key_down(qk) else 0)
            return True

        elif swicode == llapi.LLAPI_THREAD_CREATE:
            pcode = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            stack = self.emu.reg_read(arm_const.UC_ARM_REG_R1)
            stackSz = self.emu.reg_read(arm_const.UC_ARM_REG_R2) * 4
            par = self.emu.reg_read(arm_const.UC_ARM_REG_R3)

            self.thread_list[self.tid] = {}
            self.thread_list[self.tid]["context"] = self.emu.context_save()
            self.thread_list[self.tid]["context"].reg_write(arm_const.UC_ARM_REG_R0, par)
            self.thread_list[self.tid]["context"].reg_write(arm_const.UC_ARM_REG_SP, (stack + stackSz - 4) & (~0b111)) # align to 8
            self.thread_list[self.tid]["context"].reg_write(arm_const.UC_ARM_REG_R14, 0) # set return address to NULL
            self.thread_list[self.tid]["delay"] = 0
            self.thread_list[self.tid]["PC"] = pcode
            self.tid += 1
            # print("Create Thread:%08X" % pcode)
            return True
        
        elif swicode == llapi.LLAPI_APP_DELAY_MS:
            #time.sleep(self.emu.reg_read(arm_const.UC_ARM_REG_R0)/1000.0)
            delay_ms = self.emu.reg_read(arm_const.UC_ARM_REG_R0)
            ms = int(time.time_ns() / 1_000_000)
            self.thread_list[self.select_thread]["delay"] = ms + delay_ms
            # print(f"Thread: {self.select_thread}, Delay: {delay_ms}")
            return True
        
        # print("Unknown SWI CODE:%08X" % swicode)
        return False
    
    def runtime_status(self):
        while True:
            time.sleep(1)
            # print("Freq: ~%d MC/s" % (self.run_cnt/1000000))
            self.run_cnt = 0

    def thread_switch(self):
        # print("================")
        # find next thread
        self.select_thread += 1
        finding_next_thread = True # should we continue finding
        while finding_next_thread:
            for tid in self.thread_list:
                if tid >= self.select_thread:
                    # print(f"thread found {tid}")
                    finding_next_thread = False
                    self.select_thread = tid
                    break
            if finding_next_thread:
                # not found, reset and try again
                self.select_thread = 0
                continue
            if self.thread_list[self.select_thread]["delay"] > int(time.time_ns() / 1_000_000):
                # in delay, find next
                # print(f"    thread in delay {self.select_thread}")
                self.select_thread += 1
                self.select_thread %= self.tid
                finding_next_thread = True
                continue
        self.thread_list[self.select_thread]["delay"] = 0 # clear delay
        # print(f"current tid: {self.select_thread}\n")
    
    def thread_context_save(self):
        self.emu.context_update(self.thread_list[self.select_thread]["context"])
        self.thread_list[self.select_thread]["PC"] = self.emu.reg_read(arm_const.UC_ARM_REG_PC)
    
    def thread_context_restore(self):
        self.emu.context_restore(self.thread_list[self.select_thread]["context"])
        self.emu.reg_write(arm_const.UC_ARM_REG_PC, self.thread_list[self.select_thread]["PC"])

    def emu_thread(self):
        self.run_cnt = 0

        #self.runtime_status_t = threading.Thread(target=self.runtime_status)
        #self.runtime_status_t.daemon = True
        #self.runtime_status_t.start()
        
        self.t0 = datetime.datetime.now().timestamp()
        self.t1 = datetime.datetime.now().timestamp()
        self.t2 = datetime.datetime.now().timestamp()

        self.select_thread = 0
        self.thread_list[self.tid] = {}
        self.thread_list[self.tid]["context"] = self.emu.context_save()
        self.thread_list[self.tid]["context"].reg_write(arm_const.UC_ARM_REG_SP, self.EXP_RAM_ADDR + self.EXP_RAM_SZ - 8)
        self.thread_list[self.tid]["PC"] = self.EXP_ROM_ADDR + 4 * 8
        self.thread_list[self.tid]["delay"] = 0
        self.tid += 1

        # self.rc = 1000000
        self.rc = 100000
        while(self.run):
            self.thread_switch()
            try:
                try:
                    self.thread_context_restore()
                    tmode = ((self.emu.reg_read(arm_const.UC_ARM_REG_CPSR) & (1 << 5)) > 0)
                    self.emu.emu_start(
                        self.thread_list[self.select_thread]["PC"] if not tmode else self.thread_list[self.select_thread]["PC"] | 1, 
                        self.EXP_ROM_ADDR + self.exp_size,0,self.rc
                    )
                    self.thread_context_save()
                    self.run_cnt += self.rc 
                except unicorn.UcError as e:
                    if e.errno == unicorn.UC_ERR_EXCEPTION:
                        # llapi exception
                        self.CurPC = self.emu.reg_read(arm_const.UC_ARM_REG_PC) 
                        if(self.do_llapi() == False):
                            raise
                        self.emu.reg_write(arm_const.UC_ARM_REG_PC, self.CurPC)
                        self.thread_context_save()
                        continue
                    elif e.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
                        # maybe thread end.
                        retn_addr = self.emu.reg_read(arm_const.UC_ARM_REG_R14)
                        pc_ptr = self.emu.reg_read(arm_const.UC_ARM_REG_PC)
                        if retn_addr == 0 and pc_ptr == 0:
                            # ignore error, it maybe sub thread end.
                            print(f"(THREAD {self.select_thread} END)")
                            del self.thread_list[self.select_thread]
                            continue
                    raise
            except unicorn.UcError as e:
                self.dumpreg()
                self.run = False
                print_exc()
