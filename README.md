# TSSessions

Reports detailed information about Windows terminal services (a.k.a., "remote desktop") sessions, window stations, and desktops,
optionally also reporting the processes running in each session, the top-level windows associated with each desktop, and the
security descriptors of each window station and desktop. If executed by the System account, the sessions' information includes
information about the logged-on user's token and associated LSA logon session -- or tokens, in the case of a UAC "protected 
administrator" with both Medium and High integrity level LSA sessions.

```
Usage:

  TSSessions.exe [-p] [-w|-wv] [-sd|-sddl] [-o outfile]

-p         : List the processes associated with each terminal session
-w         : List the top-level windows associated with each desktop
-wv        : List the visible top-level windows associated with each desktop
-sd        : Show the detailed security descriptors of window stations and desktops
-sddl      : Show the security descriptos of window stations and desktops in Security Descriptor Definition Language
-o outfile : output to a named UTF-8 file. If -o not used, outputs to stdout.
```

Sample outputs [here](https://github.com/AaronMargosis/TSSessions/tree/master/Sample%20outputs).
