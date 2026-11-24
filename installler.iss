[Setup]
AppName=Sentinel
AppVersion=1.0
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
OutputDir=installer
OutputBaseFilename=Sentinel_Setup
SetupIconFile="E:\Python_Ispace\fim_project_1\Sentinel.ico"
UninstallDisplayIcon={app}\Sentinel.exe

[Files]
Source: "dist\Sentinel.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sentinel"; Filename: "{app}\Sentinel.exe"
Name: "{autodesktop}\Sentinel"; Filename: "{app}\Sentinel.exe"

[Run]
Filename: "{app}\Sentinel.exe"; Description: "Launch Sentinel"; Flags: postinstall nowait skipifsilent