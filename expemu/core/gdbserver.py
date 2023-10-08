
import socket
import threading
import re
import unicorn
import time
import atexit
from unicorn import Uc
from unicorn import arm_const

GDB_PACK_MRE = "vMustReplyEmpty"
GDB_PACK_NACK = "QStartNoAckMode"
GDB_REP_SUPPORT = "PacketSize=1024;hwbreak+;qXfer:features:read+;QStartNoAckMode+"
GDB_REP_OK = "OK"
GDB_XML_TARGET = "l<?xml version=\"1.0\"?><!DOCTYPE target SYSTEM \"gdb-target.dtd\"><target><architecture>arm</architecture><xi:include href=\"arm-core.xml\"/></target>"
GDB_XML_ARM_CORE = "l<?xml version=\"1.0\"?><!DOCTYPE feature SYSTEM \"gdb-target.dtd\"><feature name=\"org.gnu.gdb.arm.core\"><reg name=\"r0\" bitsize=\"32\"/><reg name=\"r1\" bitsize=\"32\"/><reg name=\"r2\" bitsize=\"32\"/><reg name=\"r3\" bitsize=\"32\"/><reg name=\"r4\" bitsize=\"32\"/><reg name=\"r5\" bitsize=\"32\"/><reg name=\"r6\" bitsize=\"32\"/><reg name=\"r7\" bitsize=\"32\"/><reg name=\"r8\" bitsize=\"32\"/><reg name=\"r9\" bitsize=\"32\"/><reg name=\"r10\" bitsize=\"32\"/><reg name=\"r11\" bitsize=\"32\"/><reg name=\"r12\" bitsize=\"32\"/><reg name=\"sp\" bitsize=\"32\" type=\"data_ptr\"/><reg name=\"lr\" bitsize=\"32\"/><reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\"/><reg name=\"cpsr\" bitsize=\"32\" regnum=\"25\"/></feature>"

HAL_BREAKINST_ARM      =    0xE7FFDEFE
HAL_BREAKINST_THUMB    =    0xBEBE

TIME_FOR_WAITING_SUSPEND  =  0.5

class GDBServer:
    def __init__(self, emulator) -> None:
        self.emu_sys = emulator
        self.emu:Uc = self.emu_sys.get_internal_emu()
        self.gdb_select_thread = 0
        self.client_socket = None

        self.emu.hook_add(unicorn.UC_HOOK_INSN_INVALID,
                          self.emu_inval_ins_hook,
                          self.emu_sys.EXP_ROM_ADDR,
                          self.emu_sys.EXP_ROM_ADDR + self.emu_sys.get_exp_size())

        self.hwbreak = []
    
    def start_server(self, port):
        self.gdb_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.gdb_server.bind(('localhost', port))
        self.gdb_server.listen(1)
        atexit.register(lambda: self.gdb_server.close())
        print(f"GDB server start at localhost:{port}, Waiting for GDB attach...")
        self.server_thread_t = threading.Thread(target=self.server_thread)
        self.server_thread_t.daemon = True
        self.server_thread_t.start()

    def emu_inval_ins_hook(self, uc:Uc, userdata):
        self.emu_sys.notify_suspend()
        uc.emu_stop()
        
        self.gdb_select_thread = self.emu_sys.get_running_thread_id()
        pc = uc.reg_read(arm_const.UC_ARM_REG_PC)
        print("GDB: Break:%08x" % pc)
        print("GDB: sw hook Break at thread:", self.gdb_select_thread)
        self.send_rep("S%1d5" % self.gdb_select_thread) 

    def emu_hookcode_cb(self, uc:Uc, address, size, user_data):
        self.emu_sys.notify_suspend()
        uc.emu_stop()
        pc = uc.reg_read(arm_const.UC_ARM_REG_PC)
        print("GDB: Break:%08x" % pc)

        self.gdb_select_thread = self.emu_sys.get_running_thread_id()
        print("GDB: hw hook Break at thread:", self.gdb_select_thread)
        self.send_rep("S%1d5" % self.gdb_select_thread) 
        #self.send_rep("S05") 
        

    def send_rep(self, d):
        retry = 0
        while self.client_socket is None:
            print("GDB: Waiting...")
            time.sleep(1)
            retry += 1
            if retry > 3:
                return
        chksum = 0
        for i in d:
            chksum += ord(i)
        chksum = chksum & 0xFF
        dat = "+$%s#%02X" % (d, chksum)
        #print("Send:",dat)
        dat = dat.encode()
        self.client_socket.send(dat)

    def suspend_emu(self, s:bool):
        if s:
            self.emu_sys.wait_for_suspend()
        else:
            self.emu.ctl_flush_tb()
            self.emu_sys.resume()

    def server_thread(self):
        while True:
            self.client_socket = None
            self.client_socket, self.client_address = self.gdb_server.accept()
            print("GDB Connected.")
            self.emu_sys.update_gdb_status(True)
            self.suspend_emu(True)
            while True:
                dat = self.client_socket.recv(1024)
                dat = dat.decode()
                if(len(dat) == 0):
                    self.emu_sys.update_gdb_status(False)
                    self.suspend_emu(False)
                    print("GDB disconnected.")
                    break
                
                if(dat[0] == '\03'):
                    self.suspend_emu(True)
                    self.gdb_select_thread = self.emu_sys.get_running_thread_id()
                    print("GDB: ESC Break at thread:", self.gdb_select_thread)
                    self.send_rep( "S%1d5" % self.gdb_select_thread) 

                if(dat[0] == '+'):
                    dat = dat[1:]
                if(len(dat) > 0):
                    if(dat[0] == '$'):
                        #print("Cont", dat[1:])
                        if(dat[1:].startswith("qSupported")):
                            self.send_rep( GDB_REP_SUPPORT)
                        elif(dat[1:].startswith(GDB_PACK_MRE)):
                            self.send_rep( "")
                        elif dat[1:].startswith(GDB_PACK_NACK) :
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("H") :  #H op threadid:  
                            sub_dat = dat[2:]
                            if sub_dat[1] != '-':
                                self.gdb_select_thread = int(sub_dat[1])
                                print("GDB: Select thread:", self.gdb_select_thread)
                                if sub_dat[0] == 'g':
                                    self.send_rep( GDB_REP_OK)
                                else:
                                    self.send_rep( "")
                            else:
                                self.send_rep( "")

                        elif dat[1:].startswith("qTStatus") :
                            self.send_rep( "")
                        elif dat[1:].startswith("qfThreadInfo") :
                            print("GDB: Query thread num:", self.emu_sys.get_thread_count())
                            send_str = "m"
                            for i in range(0, self.emu_sys.get_thread_count()):
                                send_str += ("%d," % i)
                            self.send_rep( send_str)
                        elif dat[1:].startswith("qsThreadInfo") :
                            self.send_rep( "l")
                        elif dat[1:].startswith("T") : # Txx thread alive  ,ENN: thread is dead
                            self.send_rep( GDB_REP_OK)

                        elif dat[1:].startswith("qL1200000000000000000") :
                            self.send_rep( "")
                        elif dat[1:].startswith("Hc-1") :
                            self.send_rep( "")
                        elif dat[1:].startswith("qC") :
                            self.send_rep( "")
                        elif dat[1:].startswith("qOffsets") :
                            self.send_rep( "")
                        elif dat[1:].startswith("qAttached") :
                            self.send_rep( "1")
                        elif dat[1:].startswith("qSymbol") :
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("?") : # asks for a reason why the target halted.
                            self.send_rep( "S05") # POSIX signal 5=SIGTRAP
                        elif dat[1:].startswith("qXfer:features:read:target.xml") :
                            self.send_rep( GDB_XML_TARGET)
                        elif dat[1:].startswith("qXfer:features:read:arm-core.xml") :
                            self.send_rep( GDB_XML_ARM_CORE)
                        #elif dat[1:].startswith("vCont?") :
                        #    self.send_rep("vCont;c;t") #support cont,stop,
                        elif dat[1:].startswith("vCtrlC") :
                            self.suspend_emu(True)
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("c") : #continue
                            self.suspend_emu(False)
                            self.send_rep( GDB_REP_OK) #‘C sig[;addr]’
                        elif dat[1:].startswith("s") : #step
                            self.suspend_emu(False)
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("D") : #detached
                            self.suspend_emu(False)
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("S") : # step with signal
                            self.suspend_emu(False)
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("C") : # continue with signal
                            self.suspend_emu(False)
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("vKill") :
                            self.send_rep( GDB_REP_OK)
                        elif dat[1:].startswith("g") : 
                            regs = []
                            thread_cont = self.emu_sys.get_running_thread_obj(self.gdb_select_thread)["context"]
                            for i in range(arm_const.UC_ARM_REG_R0, arm_const.UC_ARM_REG_R12 + 1):
                                regs.append(int.from_bytes(thread_cont.reg_read(i).to_bytes(4,"big"), "little"))
                            
                            regs.append(int.from_bytes(thread_cont.reg_read(arm_const.UC_ARM_REG_R13).to_bytes(4,"big"), "little"))
                            regs.append(int.from_bytes(thread_cont.reg_read(arm_const.UC_ARM_REG_R14).to_bytes(4,"big"), "little"))
                            regs.append(int.from_bytes(self.emu_sys.get_running_thread_obj(self.gdb_select_thread)["PC"].to_bytes(4,"big"), "little"))
                            regs.append(int.from_bytes(thread_cont.reg_read(arm_const.UC_ARM_REG_CPSR).to_bytes(4,"big"), "little"))

                            st = ""
                            for i in regs:
                                st += ("%08lX" % (i))
                            self.send_rep( st)

                        elif dat[1:].startswith("P") : #write a register
                            Reg = re.findall(r'P.*?=', dat)
                            Reg = int(Reg[0][1:-1], base=16)
                            Val = re.findall(r'=.*?#', dat)
                            Val = int(Val[0][1:-1], base=16).to_bytes(4, 'big')
                            Val = int.from_bytes(Val, 'little', signed = False)
                            print("GDB: Set REG:%d = %08x" % (Reg, Val))

                            if Reg <= 12:
                                regc = arm_const.UC_ARM_REG_R0 + Reg
                            elif Reg == 13:
                                regc = arm_const.UC_ARM_REG_SP
                            elif Reg == 14:
                                regc = arm_const.UC_ARM_REG_LR
                            
                            if Reg != 15:
                                self.emu_sys.get_running_thread_obj(self.gdb_select_thread)["context"].reg_write(regc, Val)
                            else:
                                self.emu_sys.get_running_thread_obj(self.gdb_select_thread)["PC"] = Val

                            self.send_rep( GDB_REP_OK)

                        #elif dat[1:].startswith("G") : 
                        #    self.send_rep( GDB_REP_OK)
                            

                        elif dat[1:].startswith("m") : #read mem
                            addr = re.findall(r'm.*?,', dat)
                            addr = int(addr[0][1:-1], base=16)
                            sz = re.findall(r',.*?#', dat)
                            sz = int(sz[0][1:-1], base=16)
                            try:
                                rdat = self.emu.mem_read(addr, sz)
                            except:
                                rdat = None
                            if rdat is not None:
                                strs = ""
                                for i in rdat:
                                    strs += ("%02X" % i)
                                self.send_rep( strs)
                            else:
                                self.send_rep( "")

                        elif dat[1:].startswith("M") : #write mem
                            addr = re.findall(r'M.*?,', dat)
                            addr = int(addr[0][1:-1], base=16)
                            sz = re.findall(r',.*?:', dat)
                            sz = int(sz[0][1:-1], base=16)
                            wrdat = re.findall(r':.*?#', dat)
                            wrdat = wrdat[0][1:-1]
                            print("GDB: mem write:%08X, %d :" % (addr, sz), wrdat)
                            while sz:
                                byte = wrdat[0:2]
                                wrdat = wrdat[2:]
                                byte = int(byte, base=16).to_bytes(1, "little")
                                self.emu.mem_write(addr, byte)
                                addr += 1
                                sz -= 1
                            
                            self.send_rep( GDB_REP_OK)

                        elif dat[1:].startswith("Z") : #Z0,800359c,4#b2 Set hwbreak
                            last_status = self.emu_sys.wait_for_suspend()
                            addr = re.findall(r',.*?,', dat)
                            addr = int(addr[0][1:-1], base=16)
                            sz = re.findall(r',.*?#', dat[4:])
                            sz = int(sz[0][1:-1], base=16)
                            print("GDB: Set HW Breakpoint:%08x,%d" % (addr, sz))
                            h = self.emu.hook_add(unicorn.UC_HOOK_CODE, self.emu_hookcode_cb, begin=addr, end=addr + sz)
                            self.hwbreak.append((addr, h))
                            self.send_rep(GDB_REP_OK)
                            if last_status:
                                self.emu_sys.resume()
 
                            
                        elif dat[1:].startswith("z") : #Z0,800359c,4#b2 del hwbreak
                            last_status = self.emu_sys.wait_for_suspend()
                            addr = re.findall(r',.*?,', dat)
                            addr = int(addr[0][1:-1], base=16)
                            sz = re.findall(r',.*?#', dat[4:])
                            sz = int(sz[0][1:-1])
                            ind = 0
                            for adr,h in self.hwbreak:
                                if adr == addr:
                                    self.emu.hook_del(h)
                                    print("GDB: Del HW Breakpoint:%08x,%d" % (addr, sz))
                                    self.hwbreak.pop(ind)
                                ind += 1
 
                            self.send_rep(GDB_REP_OK)
                            if last_status:
                                self.emu_sys.resume()


                        else:
                            self.send_rep( "")


