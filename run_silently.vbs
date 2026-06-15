Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "c:\Users\pglap\OneDrive\Desktop\add blocker"
WshShell.Run "C:\Python314\python.exe block_ads.py", 0, False
