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
    matches = []

    def __init__(self, bv):
        super(YaraScan, self).__init__()
        self.bv = bv
        self.start = self.bv.start
        self.end = self.bv.end
        self.size = self.end - self.start
        self.load_binary()
        self.load_signatures()
        log.log(1, "scanning binary %s" % bv.file.filename)
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
                log.log(3, "%s is no directory" % YARA_SIGNATURE_DIR)
                sys.exit(-1)
        except OSError as e:
            if "No such file or directory" in e:
                # create new directory
                log.log(2, "creating %s" % YARA_SIGNATURE_DIR)
                os.mkdir(YARA_SIGNATURE_DIR)
            else:
                log.log(3, "could not read %s" % YARA_SIGNATURE_DIR)
                sys.exit(-1)
        yara_files = [dir for dir in os.listdir(YARA_SIGNATURE_DIR) if ".yar" in dir[-4:]]
        for yara_file in yara_files:
            log.log(1, "loading %s" % yara_file)
            try:
                self.rules.append(yara.compile(filepath=YARA_SIGNATURE_DIR + "/" + yara_file))
            except yara.SyntaxError as e:
                log.log(2, "error compiling %s" % yara_file)

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
            log.log(1, "0x%x rule %s string %s" % (match_addr, data['rule'], matched_string))
            self.matches.append({ "rule": data['rule'], "address": match_addr, "string": matched_string })
            if self.bv.is_offset_executable(match_addr):
                # comments are unfortunately only available in executable code
                bbs = self.bv.get_basic_blocks_at(match_addr)
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

    def display_matches(self, bv):
        html = str()
        plaintext = str()
        html += "<!DOCTYPE html>\n"
        html += "<html>\n\t<body>\n"
        html += "<center>\n"
        html += "<table>\n"
        html += "<tr>\n"
        html += "<th width=\"400\">rule</th>\n"
        html += "<th width=\"400\">address</th>\n"
        html += "<th width=\"400\">string</th>\n"
        html += "</tr>\n"
        for m in self.matches:
            html += "<tr>\n"
            html += "<td>%s</td>\n" % m["rule"]
            html += "<td>0x%x</td>\n" % m["address"]
            html += "<td>%s</td>\n" % m["string"]
            html += "</tr>\n"
        html += "</table>\n"
        html += "</center>\n"
        html += "\t</body>\n</html>"
        bv.show_html_report("Yara matches", html, plaintext)

def yara_scan(bv):
    ys = YaraScan(bv)
    ys.display_matches(bv)

PluginCommand.register("Yara Scan", "Scan the current binary with yara", yara_scan)
