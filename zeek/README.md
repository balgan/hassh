# hassh.zeek
[![License: BSD 3-Clause License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

## Features
**hassh.zeek** adds these fields to your Zeek ssh.log file
- hasshVersion
- hassh, hasshAlgorithms
- hasshServer, hasshServerAlgorithms
- cshka (Client Host Key Algorithms), sshka (Server Host Key Algorithms)

Version 2.0 of the script needs Zeek 3.0 or newer and is tested on Zeek 9.0. Zeek (formerly Bro) releases before 2.6.0 reversed the client/server flag (https://github.com/zeek/zeek/pull/191); if you are still on one of those, use version 1.5 of this script.

## Installation
With the Zeek Package Manager:
```bash
zkg install hassh
```
or place the `zeek` directory in `<prefix>/share/zeek/site/hassh` and add this line to your local.zeek script:
```zeek
@load ./hassh
```

## Configuration
Which fields are logged is controlled by three options; no need to edit the script any more:

| option | default | fields |
|---|---|---|
| `SSH::hassh_log_algorithms` | `T` | hasshAlgorithms, hasshServerAlgorithms |
| `SSH::hassh_log_host_key_algorithms` | `T` | cshka, sshka |
| `SSH::hassh_log_components` | `F` | ckex, ceacts, cmacts, ccacts, skex, seastc, smastc, scastc |

For example, to log only the fingerprints, in local.zeek:
```zeek
redef SSH::hassh_log_algorithms = F;
redef SSH::hassh_log_host_key_algorithms = F;
```
Fields that are switched off stay unset and are logged as `-`.

## Credits:
HASSH was conceived and developed by [Ben Reardon](mailto:breardon@salesforce.com) (@benreardon) within the Detection Cloud Team at Salesforce, with inspiration and contributions from [Adel Karimi](mailto:akarimishiraz@salesforce.com) (@0x4d31) and the [JA3 crew](https://github.com/salesforce/ja3/)  crew:[John B. Althouse](mailto:jalthouse@salesforce.com)  , [Jeff Atkinson](mailto:jatkinson@salesforce.com) and [Josh Atkins](mailto:j.atkins@salesforce.com)
