# Import the libraries we need
import frida
import sys
import msvcrt
import time
import os
import argparse
import glob
import csv
import re


# Global variables
VERBOSE = False
TIMEOUT = 10

"""
Class to timeout binary execution in frida
Thanks to an unsung hero on stack overflow
"""
class TimeoutExpired(Exception):
    pass

def stdin_with_timeout(timeout, timer=time.monotonic):
    sys.stdout.flush()
    endtime = timer() + timeout
    result = []
    while timer() < endtime:
        if msvcrt.kbhit():
            result.append(msvcrt.getwche()) #XXX can it block on multibyte characters?
            if result[-1] == '\n':   #XXX check what Windows returns here
                return ''.join(result[:-1])
        time.sleep(0.04) # just to yield to other processes/threads
    raise TimeoutExpired

"""
Override Frida's on_message method to receive data from Frida's instrumentation
"""
def on_message(message, data):
    if VERBOSE:
        print(message)
    try:
        with open("temp.log", "a") as f:
            f.write(message['payload'] + "\n")
    except:
        if VERBOSE:
            print(f"[!] Error: {message}")

"""
Function to identify dll hijacking/sideloading with Frida
"""
def dll(target_process, timeout=TIMEOUT):
    # Check for working directory execution or full path execution
    if ".\\" in target_process:
        target_pid = frida.spawn(f".\{target_process}")
    else:
        target_pid = frida.spawn(f"{target_process}")

    # Attach our local device to the target process id
    session = frida.attach(target_pid)
    # Read our frida script to hook loadlibrary and getprocaddress
    with open(".\\loadlibrary.js", "r") as f:
        contents = f.read()
    
    # Create our script in our frida session
    script = session.create_script(contents)
    # Tell Frida to use on_message when "message" in called
    script.on('message', on_message)
    # Load the script
    script.load()
    # Resume the process
    frida.resume(target_pid)
    # Timeout hack
    try:
        stdin_with_timeout(timeout)
    except TimeoutExpired:
        pass
    # Detatch from our session after timeout occurs
    session.detach()
    # Make sure our process terminates
    frida.kill(target_pid)
    # List to store our results
    results = []
    # Pretty output
    print("-"*50)
    # Open and read the temp log created from on_message()
    try:
        with open("temp.log", "r") as f:
            results = f.read().splitlines()
    except FileNotFoundError:
        print(f"[*] No potential dll sideloading in {target_process}")
    # If this is an absolute path, grab the exe name with regex
    if "\\" in target_process and ":" in target_process:
        match = re.search("\w+\.exe", target_process)
        # If the regex matches, define target_process as the exe name instead of absolute path
        if match:
            target_process = match.group()
    # list to store our potential dll sideload
    potential_sideload = []
    # Open a sideload log file for target exe
    with open(f"{target_process}-sideload.log", "w") as f:
        # Iterate over our results from frida
        for result in results:
            # loadlibrary in a result means potential dllmain sideload opportunity
            if "loadlibrary" in result.lower():
                potential_sideload.append(f"{target_process},{result}".split(","))
                f.write(f"[+] Potential DllMain Sideloading: {result}\n")
                print(f"\t[+] Potential DllMain Sideloading: {result}")
            # loadlibrary not in a result means an export is called via getprocaddress
            # potential dllexport sideload opportunity
            else:
                potential_sideload.append(f"{target_process},{result}".split(","))
                f.write(f"[-] Potential DllExport Sideloading: {result}\n")
                print(f"\t[-] Potential DllExport Sideloading: {result}")
    # Rename temp.log to raw.log for target exe
    if os.path.isfile("temp.log"):
        os.replace("temp.log", f"{target_process}-raw.log")
        print(f"\n[*] Writing raw Frida instrumentation to {target_process}-raw.log")
        print(f"[*] Writing Potential DLL Sideloading to {target_process}-sideload.log")
    print("-"*50)

    # Return the potential sideload results to write to a csv at the end
    return potential_sideload

def com(target_process, timeout=TIMEOUT):
    # Check for working directory execution or full path execution
    if ".\\" in target_process:
        target_pid = frida.spawn(f".\{target_process}")
    else:
        target_pid = frida.spawn(f"{target_process}")

    # Attach our local device to the target process id
    session = frida.attach(target_pid)
    # Read our frida script to hook loadlibrary and getprocaddress
    with open(".\\registry.js", "r") as f:
        contents = f.read()
    
    # Create our script in our frida session
    script = session.create_script(contents)
    # Tell Frida to use on_message when "message" in called
    script.on('message', on_message)
    # Load the script
    script.load()
    # Resume the process
    frida.resume(target_pid)
    # Timeout hack
    try:
        stdin_with_timeout(timeout)
    except TimeoutExpired:
        pass
    # Detatch from our session after timeout occurs
    session.detach()
    # Make sure our process terminates
    frida.kill(target_pid)
    # List to store our results
    results = []
    # Pretty output
    print("-"*50)
    # Open and read the temp log created from on_message()
    try:
        with open("temp.log", "r") as f:
            results = f.read().splitlines()
    except FileNotFoundError:
        print(f"[*] No potential com hijack in {target_process}")
    # If this is an absolute path, grab the exe name with regex
    if "\\" in target_process and ":" in target_process:
        match = re.search("\w+\.exe", target_process)
        # If the regex matches, define target_process as the exe name instead of absolute path
        if match:
            target_process = match.group()
    # list to store our potential com hijacks
    potential_comhijack = []
    # open a comhijack log for target exe
    with open(f".\\{target_process}-comhijack.log", "w") as f:
        # iterate over our results from frida
        for result in results:
            f.write(f"[+] Potential COM Hijack: {result}\n")
            print(f"\t[+] Potential COM Hijack: {result}")
            potential_comhijack.append(f"{target_process},{result}".split(","))
    # Rename temp.log to raw.log for target exe
    if os.path.isfile("temp.log"):
        os.replace("temp.log", f".\\{target_process}-raw.log")
        print(f"\n[*] Writing raw Frida instrumentation to .\\{target_process}-raw.log")
        print(f"[*] Writing Potential COM Hijack to .\\{target_process}-comhijack.log")
    print("-"*50)
    # return the potential com hijacks to write to a csv at the end
    return potential_comhijack

def main():
    epilog = """EXAMPLE USAGE
    NOTE: It is recommended to copy target binaries to the same directory as WFH for identifying DLL Sideloading
    
    DLL Sideloading Identification (Single):        python wfh.py -t .\mspaint.exe -m dll
    DLL Sideloading Identification (Verbose):       python wfh.py -t .\mspaint.exe -m dll -v
    DLL Sideloading Identification (Timeout 30s):   python wfh.py -t .\mspaint.exe -m dll -timeout 30
    DLL Sideloading Identification (Wildcard):      python wfh.py -t * -m dll
    DLL Sideloading Identification (List):          python wfh.py -t .\mspaint.exe .\charmap.exe -m dll

    COM Hijacking Identification (Single):          python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com
    COM Hijacking Identification (Verbose):         python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com -v
    COM Hijacking Identification (Timeout 60s):     python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" -m com -timeout 60
    COM Hijacking Identification (Wildcard):        python wfh.py -t * -m com -v
    COM Hijacking Identification (List):            python wfh.py -t "C:\Program Files\Internet Explorer\iexplore.exe" "C:\Windows\System32\\notepad.exe" -m com -v
    """
    # CLI Arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Windows Feature Hunter", epilog=epilog)
    parser.add_argument('-t', '-targets', action="store", nargs="+", required=True, help="list of target windows executables")
    parser.add_argument('-m', "-mode", action="store", choices=["dll", "com"], required=True, help="vulnerabilities to potentially identify")
    parser.add_argument('-v', '-verbose', action="store_true", help="verbose output from Frida instrumentation")
    parser.add_argument('-timeout', action="store", help="timeout value for Frida instrumentation")

    args = parser.parse_args()

    # Check to see if the user wants verbose output
    if args.v:
        VERBOSE = True

    # Check to see if the user wants to customize the timeout value for a target exe
    if args.timeout:
        TIMEOUT = args.timeout

    # Check if we're identifying dll sideloading
    if args.m == "dll":
        # Make sure our targets argument is not empty
        if args.t:
            # list to store all the results
            all_results = []
            # CSV header
            header = ["Executable", "WinAPI", "DLL", "EntryPoint / WinAPI Args"]
            # Check if we want to use wildcards
            if args.t[0].endswith("*"):
                for exe in glob.glob(args.t[0] + ".exe"):
                    print("="*50)
                    print(f"Running Frida against {exe}")
                    try:
                        results = dll(exe)
                        all_results.append(results)
                    except:
                        pass
            else:
                # iterate over our target exes
                for exe in args.t:
                    print("="*50)
                    print(f"Running Frida against {exe}")
                    results = dll(exe)
                    all_results.append(results)

            print("="*50)
            print("[*] Writing dll results to dll_results.csv")
            # write the results to dll_results.csv
            with open('dll_results.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for result in all_results:
                    writer.writerows(result)
    # Check if we're identifying com hijacks
    elif args.m == "com":
        # Make sure our targets argument is not empty
        if args.t:
            # list to store all the results
            all_results = []
            # CSV header
            header = ["Executable", "Path", "ValueName", "Type", "Value"]
            # Check if we want to use wildcards
            if args.t[0].endswith("*"):
                for exe in glob.glob(args.t[0] + ".exe"):
                    print("="*50)
                    print(f"Running Frida against {exe}")
                    try:
                        results = com(exe)
                        all_results.append(results)
                    except:
                        pass
            else:
                # iterate over our target exes
                for exe in args.t:
                    print("="*50)
                    print(f"Running Frida against {exe}")
                    results = com(exe)
                    all_results.append(results)
            
            print("="*50)
            print("[*] Writing dll results to comhijack_results.csv")
            # write the results to comhijack_results.csv
            with open('comhijack_results.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)
                for result in all_results:
                    writer.writerows(result)

    else:
        print("[!] Unsupported option")

if __name__ == "__main__":
    sys.exit(main())