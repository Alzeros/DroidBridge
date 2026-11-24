' Create a Desktop shortcut for DroidBridge with its icon.
Option Explicit
Dim sh, fso, here, desktop, lnkPath, sc
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
desktop = sh.SpecialFolders("Desktop")
lnkPath = fso.BuildPath(desktop, "DroidBridge.lnk")

Set sc = sh.CreateShortcut(lnkPath)
sc.TargetPath = sh.ExpandEnvironmentStrings("%SystemRoot%\System32\wscript.exe")
sc.Arguments = """" & fso.BuildPath(here, "launch_droidbridge.vbs") & """"
sc.WorkingDirectory = here
sc.IconLocation = fso.BuildPath(here, "droidbridge.ico") & ",0"
sc.Description = "DroidBridge - per-app network bridge over ADB"
sc.Save

MsgBox "Desktop shortcut created: " & lnkPath, vbInformation, "DroidBridge"
