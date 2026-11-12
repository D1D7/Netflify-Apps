' NetAgent in the background (no window). Restarts it if it stops,
' until logs\stop.flag exists (autostart-off.bat creates it).
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
sh.Environment("PROCESS")("PYTHONUTF8") = "1"
If Not fso.FolderExists(dir & "\logs") Then fso.CreateFolder(dir & "\logs")
flag = dir & "\logs\stop.flag"
If fso.FileExists(flag) Then fso.DeleteFile(flag)
cmd = """" & dir & "\.venv\Scripts\pythonw.exe"" -m netagent serve --log-file """ & dir & "\logs\netagent.log"""
Do
  sh.Run cmd, 0, True
  If fso.FileExists(flag) Then Exit Do
  WScript.Sleep 15000
Loop
