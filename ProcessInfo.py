# Process Information for Monitor Daemon
import os

from process_watcher.pywinapi.kernel32.processthreadsapi import open_process_queryinfo
from process_watcher.pywinapi.kernel32.handleapi import close_handle
from process_watcher.pywinapi.kernel32.wow64apiset import is_wow64_process
from process_watcher.pywinapi.ntdll import GetProcessBasicInfo
from process_watcher.pywinapi.psapi import get_module_filename_ex_w


class ProcessInfo(object):
    def __init__(self, pid):
        self.pid = pid
        self.parent_pid = -1
        self.name = ""
        self.path = ""
        self.arch = -1
        self.valid = self.get_info()

    def get_info(self):
        # Open Process Handle for Reading
        res, h_process = open_process_queryinfo(self.pid)
        if not res:
            return False

        # Get Parent PID
        res, pbi = GetProcessBasicInfo(h_process)
        if not res:
            close_handle(h_process)
            return False
        self.parent_pid = pbi.InheritedFromUniqueProcessId

        # Get Module Path [Normalized]
        res, self.path = get_module_filename_ex_w(h_process)
        self.path = self.path.lower()
        if not res:
            close_handle(h_process)
            return False

        # Get Module Filename [Normalized]
        self.name = os.path.basename(self.path)


        # Get Architecture
        res, is_wow64 = is_wow64_process(h_process)
        if not res:
            close_handle(h_process)
            return False

        if is_wow64:
            self.arch = 32
        else:
            self.arch = 64

        # Set Valid Flag
        return True
