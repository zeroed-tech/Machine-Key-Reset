Published alongside https://zeroed.tech/blog/viewstate-the-unpatchable-iis-forever-day-being-actively-exploited/

Run the auditer with one of the following commands:

```
.\IIS-Machine-Key-Audit.ps1
.\IIS-Machine-Key-Audit.ps1 | Format-Table
.\IIS-Machine-Key-Audit.ps1 | Select ApplicationPool, UserName, MachineKeyFound,Created,Path | Format-Table
```

After ensuring you have a backup of your host, reset keys using:

```
.\IIS-Machine-Key-Reset.ps1 -accept
```
