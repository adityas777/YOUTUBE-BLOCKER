import ctypes
import os
import sys

def main():
    dll_path = "C:\\Windows\\System32\\wpcap.dll"
    if not os.path.exists(dll_path):
        dll_path = "C:\\Windows\\sysnative\\wpcap.dll"
        
    print(f"[Diagnostic] Loading Npcap DLL from: {dll_path}")
    try:
        # Load the DLL using ctypes
        wpcap = ctypes.CDLL(dll_path)
        print("[Diagnostic] DLL loaded successfully.")
        
        # Define the pcap_if struct for ctypes
        class pcap_if(ctypes.Structure):
            pass
            
        pcap_if._fields_ = [
            ("next", ctypes.POINTER(pcap_if)),
            ("name", ctypes.c_char_p),
            ("description", ctypes.c_char_p),
            ("addresses", ctypes.c_void_p),
            ("flags", ctypes.c_uint)
        ]
        
        alldevs = ctypes.POINTER(pcap_if)()
        errbuf = ctypes.create_string_buffer(256)
        
        # Call pcap_findalldevs
        res = wpcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
        if res == -1:
            print(f"[Diagnostic] Error in pcap_findalldevs: {errbuf.value.decode()}")
            return
            
        curr = alldevs
        count = 0
        while curr:
            count += 1
            name = curr.contents.name.decode('utf-8', errors='ignore')
            desc = curr.contents.description.decode('utf-8', errors='ignore') if curr.contents.description else "No Description"
            print(f"  [{count}] Device: {name}")
            print(f"      Description: {desc}")
            curr = curr.contents.next
            
        if count == 0:
            print("[Diagnostic] Npcap resolved successfully but returned 0 interfaces.")
        else:
            print(f"[Diagnostic] Successfully found {count} interfaces.")
            wpcap.pcap_freealldevs(alldevs)
            
    except Exception as e:
        print(f"[Diagnostic Error] Failed to query Npcap DLL: {e}")

if __name__ == "__main__":
    main()
