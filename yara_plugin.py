# ==============================================================================
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Lesser General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# ==============================================================================

from binaryninja import *
import yara
import os,sys
import stat

YARA_SIGNATURE_DIR=os.environ['HOME'] + "/.binaryninja/yara"

class YaraScan(object):
    
    rules = []
    bv = 0
    start = 0
    end = 0
    size = 0
    data = [] 
    data_offsets = []
    function_EPs = []

    def __init__(self, bv):
        self.bv = bv
        self.start = self.bv.start
        self.end = self.bv.end
        self.size = self.end - self.start
        self.load_binary()
        self.load_functionEPs()
        self.load_signatures()
        log(1, "scanning binary %s" % bv.file.filename)
        self.scan()

    def load_functionEPs(self):
        addr = self.start
        last_addr = 0
        while True:
            addr = self.bv.get_next_function_start_after(last_addr)
            if addr == last_addr or (not addr):
                break
            self.function_EPs.append(addr)
            last_addr = addr

    def load_binary(self):
        off = 0
        page_size = 0x1000
        while True:
            if self.start + off >= self.start + self.size:
                # we are done
                break
            tmp = self.bv.read(self.start + off, self.size)
            if len(tmp) > 0:
                self.data.append(tmp)
                self.data_offsets.append(self.start + off)
                off = off + len(tmp)
            else:
                off_alignment = (self.start + off) % page_size
                if off_alignment:
                    next_data = self.start + off - off_alignment + page_size
                if next_data == 0:
                    # no more data
                    break
                off = next_data - self.start

    def load_signatures(self):
        try:
            ininfo = os.stat(YARA_SIGNATURE_DIR)
            if not stat.S_ISDIR(ininfo.st_mode):
                log(3, "%s is no directory" % YARA_SIGNATURE_DIR)
                sys.exit(-1)
        except OSError as e:
            if "No such file or directory" in e:
                # create new directory
                log(2, "creating %s" % YARA_SIGNATURE_DIR)
                os.mkdir(YARA_SIGNATURE_DIR)
            else:
                log(3, "could not read %s" % YARA_SIGNATURE_DIR)
                sys.exit(-1)
        yara_files = [dir for dir in os.listdir(YARA_SIGNATURE_DIR) if ".yar" in dir[-4:]]
        for yara_file in yara_files:
            log(1, "loading %s" % yara_file)
            try:
                self.rules.append(yara.compile(filepath=YARA_SIGNATURE_DIR + "/" + yara_file))
            except yara.SyntaxError as e:
                log(2, "error compiling %s" % yara_file)

    def find_function(self, addr):
            return self.bv.get_function_at(self.bv.platform, addr)

    def find_current_basic_block(self, addr):
        steps = 0x40
        while True:
            possible_bb = self.bv.get_next_basic_block_start_after(addr - steps)
            if possible_bb < addr:
                check_bb = self.bv.get_next_basic_block_start_after(possible_bb)
                if check_bb > addr:
                    return check_bb
                while True:
                    possible_bb = self.bv.get_next_basic_block_start_after(check_bb)
                    if possible_bb > addr:
                        return check_bb
                    check_bb = possible_bb
            steps = steps * 2

    def yr_callback(self, data):
        if not data['matches']:
            return yara.CALLBACK_CONTINUE
        for string in data['strings']:
            match_off = string[0]
            last_off = 0
            for off in self.data_offsets:
                if off > match_off:
                    break
                last_off = off
            addr = self.start + string[0] + last_off
            log(1, "0x%016x rule %s string %s" % (addr, data['rule'], string[2]))
            if self.bv.is_offset_executable(addr):
                # write comment
                bb_addr = self.find_current_basic_block(addr)
                bbs = self.bv.get_basic_blocks_at(bb_addr)
                for bb in bbs:
                    if bb.end > addr:
                        f = bb.function
                        f.set_comment(f.start, "0x%016x rule %s string %s" % (addr, data['rule'], string[2]))
            else:
                pass
        return yara.CALLBACK_CONTINUE

    def scan(self):
        tmp = ''
        for data in self.data:
            tmp = tmp + data
        for yr in self.rules:
            yr.match(data=tmp, callback=self.yr_callback, timeout=30)

def yara_scan(bv):
    ys = YaraScan(bv)

PluginCommand.register("Yara Scan", "Scan the current binary with yara", yara_scan)
