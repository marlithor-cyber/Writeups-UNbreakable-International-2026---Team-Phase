# control

`control` ships an Elastic/Kibana lab (`docker-compose.yml`) plus a Winlogbeat export (`index_new.json`). The challenge is a ten-question investigation over Windows process, registry, file, and security events.

The cleanest approach is to ignore Kibana entirely and parse the exported objects directly. The file is a concatenation of Winlogbeat documents, not a simple line-delimited JSON array, so the first job is to stream-decode the objects and then hunt the relevant Sysmon/Security events.

## Timeline

The intrusion chain is:

1. `msedge.exe` downloads `MicrosoftUpdate.cpl` from `http://10.13.52.111:8888/`
2. the user double-clicks it, which spawns:
   - `explorer.exe`
   - `control.exe`
   - `rundll32.exe`
3. the malware persists through `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`
4. it enumerates local users with `powershell.exe -Command Get-LocalUser`
5. it finds reusable credentials and pivots with `RunasCs.exe`
6. it abuses `SeImpersonatePrivilege` with `GodPotato-NET4.exe`
7. in the SYSTEM context it launches a fake `C:\Users\Public\explorer.exe`
8. that fake `explorer.exe` both accesses `lsass.exe` and reaches into `msedge.exe`, showing the credential-dump stage and the later process migration

## Q1. Downloaded file

The best artifact is Sysmon Event ID `15` (`FileCreateStreamHash`) for the downloaded ADS:

```text
HostUrl=http://10.13.52.111:8888/MicrosoftUpdate.cpl
```

So the file name is:

```text
MicrosoftUpdate.cpl
```

## Q2. Download server

The same ADS content gives the full host and port:

```text
10.13.52.111:8888
```

## Q3. Double-click execution chain

The relevant Sysmon Event ID `1` entries show:

1. `explorer.exe` starts `control.exe` on the `.cpl`
2. `control.exe` starts `rundll32.exe`

So the chain is:

```text
explorer.exe-control.exe-rundll32.exe
```

## Q4. Process migration target

Later in the attack, the malicious `C:\Users\Public\explorer.exe` repeatedly generates Sysmon Event ID `10` (`ProcessAccess`) against:

```text
C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```

That is the migration / injection target:

```text
msedge.exe
```

## Q5. Persistence key

Sysmon Event ID `13` (`Registry value set`) records:

```text
TargetObject: HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate
```

The question says to normalize `HKU\<sid>` to `HKCU`, so the answer is:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate
```

## Q6. Local-user enumeration

Sysmon Event ID `1` shows:

```text
powershell.exe -Command Get-LocalUser
```

## Q7. Password-reuse lateral movement

The process creation event for `RunasCs.exe` contains the full pivot command:

```text
RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"
```

## Q8. Privilege-escalation command

The SYSTEM escalation is visible as a `GodPotato-NET4.exe` process creation:

```text
GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"
```

## Q9. Exploited privilege

Security Event ID `4672` for the `steve.stevens` session includes:

```text
SeImpersonatePrivilege
```

That is the privilege abused by GodPotato.

## Q10. LSASS dumper path

Sysmon Event ID `10` shows the fake public `explorer.exe` opening `lsass.exe` with a very high access mask (`0x1fffff`):

```text
Process executable: C:\Users\Public\explorer.exe
TargetImage: C:\WINDOWS\system32\lsass.exe
```

So the process path is:

```text
C:\Users\Public\explorer.exe
```

## Final Answers

```text
Q1: MicrosoftUpdate.cpl
Q2: 10.13.52.111:8888
Q3: explorer.exe-control.exe-rundll32.exe
Q4: msedge.exe
Q5: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate
Q6: powershell.exe -Command Get-LocalUser
Q7: RunasCs.exe steve.stevens P@ssw0rd "rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"
Q8: GodPotato-NET4.exe -cmd "cmd.exe /c rundll32 shell32.dll,Control_RunDLL C:\Users\Public\MicrosoftUpdate.cpl"
Q9: SeImpersonatePrivilege
Q10: C:\Users\Public\explorer.exe
```

## Helper

[solve_control.py](./solve_control.py) parses the concatenated Winlogbeat export and prints all ten answers directly from `index_new.json`:

```bash
python3 solve_control.py /path/to/index_new.json
```
