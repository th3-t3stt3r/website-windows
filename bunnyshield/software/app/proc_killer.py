import os
import re
import time
import psutil
import subprocess
from threading import Thread
from software.config.shared_config import GeneralConfig as gc


class ProcessKiller():
    """ProcessKiller Class"""

    def __init__(self):
        self.start = time.perf_counter()
        self.malicious_process_killed = False
        self.malicious_process_detected = False
        self.malicious_pid_list = []

    #

    def checkForMaliciousProcess(self, process_whitelist):
        """Function to check which running process might be malicious"""
        threads = []

        for process in psutil.process_iter():
            is_whitelisted = False

            for whitelisted_process in process_whitelist:
                if process.pid == whitelisted_process['pid'] and process.name() == whitelisted_process['name'] and process.create_time() == whitelisted_process['create_time']:
                    is_whitelisted = True

            if not is_whitelisted:
                th = Thread(target=self.checkProcessIO, args=[process])
                th.start()
                threads.append(th)
        for th in threads:
            th.join()
        if self.malicious_process_detected:
            self.checkAndKillProcess()

    #

    def checkProcessIO(self, process):
        """Function to check how many bytes has been written by the current process"""
        start_bytes = process.io_counters().write_bytes
        time.sleep(gc.time_to_check_io)
        final_bytes = process.io_counters().write_bytes

        if (final_bytes - start_bytes) > 100000:
            self.malicious_pid_list.append(process.pid)
            self.malicious_pid_list.append(process.ppid())
            self.malicious_process_detected = True
            logger.critical(f"Ransomware Detected: {process.pid}")

    #

    def checkAndKillProcess(self):
        """Function to kill the malicious process"""
        for pid in self.malicious_pid_list:
            try:
                cwd = ""
                cwd_pattern = "(?<=\(RW-\))(.*)"
                fix_cwd_pattern = "^.*(?=([a-zA-Z]:))"
                psutil.Process(pid).status()

                logger.critical(f"Ransomware process with PID {pid}, killing it")

                try:
                    #output = subprocess.check_output(f'cd {gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER} && handle.exe -p {pid}', shell=True).decode()
                    #cwd = str(re.findall(cwd_pattern, output)[0])
                    #cwd = re.sub(fix_cwd_pattern, '', cwd)
                    cwd = psutil.Process(pid).cwd()

                except Exception as e:
                    logger.error(e)
                    pass

                try:
                    subprocess.check_output(f"taskkill /PID {pid} /F /T", shell=True)

                except Exception as e:
                    logger.error(e)
                    pass

                end = time.perf_counter()
                logger.critical(f"Killed ransomware process with PID {pid} in {round(end - self.start, 3)}s")
                if cwd:
                    logger.critical(f"Ransomware file working directory is {cwd}")
                else:
                    logger.critical(f"Could not get the Ransomware file working directory")

                return True

            except Exception as e:
                logger.error(e)
                return False


if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
