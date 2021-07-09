import time

from process_watcher import ProcessMonitor


def test_thing(pi):
    print(f"Triggered: {pi.name} [{pi.pid}//{pi.parent_pid}//{pi.arch}//]")
    return True


if __name__ == "__main__":
    targets = ["powershell.exe"]
    callback_fcn = test_thing
    child_aware = True
    match_full_paths = False
    pm = ProcessMonitor(targets, callback_fcn, child_aware, match_full_paths)
    time.sleep(10)
    del pm
    print("DonionRingz!")