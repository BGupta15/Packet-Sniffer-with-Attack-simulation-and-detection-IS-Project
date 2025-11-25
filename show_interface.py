import wmi
c = wmi.WMI()
for nic in c.Win32_NetworkAdapter():
    print(f"Name: {nic.Name}")
    print(f"Description: {nic.Description}")
    print(f"GUID: {nic.GUID}")
    print("-" * 40)
