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

    def __init__(self, bv):
        self.bv = bv
        self.start = self.bv.start
        self.end = self.bv.end
        self.size = self.end - self.start
        self.load_binary()
        self.load_signatures()
        log(1, "scanning binary %s" % bv.file.filename)
        self.scan()

    """
    traverse the linear address space in steps of 0x1000bytes (pagesize on x86) 
    in order to find mapped memory.
    likely breaks on architectures with a different pagesize.
    """
    def load_binary(self):
        off = 0
        page_size = 0x1000
        while True:
            if self.start + off >= self.start + self.size:
                # we are done
                break
            read_buffer = self.bv.read(self.start + off, self.size)
            if len(read_buffer) > 0:
                self.data.append(read_buffer)
                self.data_offsets.append(self.start + off)
                off = off + len(read_buffer)
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

    def find_current_basic_block(self, addr):
        neg_off = 0x40
        while True:
            bb_previous_bb = self.bv.get_next_basic_block_start_after(addr - neg_off)
            if bb_previous_bb < addr:
                bb_candidate = self.bv.get_next_basic_block_start_after(bb_previous_bb)
                if bb_candidate > addr:
                    return bb_candidate
                while True:
                    possible_bb = self.bv.get_next_basic_block_start_after(bb_candidate)
                    if possible_bb > addr:
                        return bb_candidate
                    bb_candidate = possible_bb
            neg_off = neg_off * 2

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
            match_addr = self.start + string[0] + last_off
            matched_string = ''.join(["%02x " % ord(c) for c in string[2]])
            log(1, "0x%x rule %s string %s" % (match_addr, data['rule'], matched_string))
            if self.bv.is_offset_executable(match_addr):
                # write comment
                bb_addr = self.find_current_basic_block(match_addr)
                bbs = self.bv.get_basic_blocks_at(bb_addr)
                for bb in bbs:
                    if bb.end > match_addr:
                        f = bb.function
                        f.set_comment(f.start, "0x%x rule %s string %s" % (match_addr, data['rule'], matched_string))
            else:
                pass
        return yara.CALLBACK_CONTINUE

    def scan(self):
        scan_buffer = ''.join(self.data)
        for yr in self.rules:
            yr.match(data=scan_buffer, callback=self.yr_callback, timeout=30)

def yara_scan(bv):
    ys = YaraScan(bv)

PluginCommand.register("Yara Scan", "Scan the current binary with yara", yara_scan)
