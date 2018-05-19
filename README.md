# LightRAT
The average reverse shell used in security testing is built for basic connectivity only, and is not feature-rich. LightRAT shells simply add embedded commands to simulate a more fully functioned reverse shell, along with some measures to prevent the shell from being accidentally terminated.

The shells have been kept intentionally light, and have only a few specific extra functions. Consequently, each new shell added to this repository will have relatively different functionality, with the exception of a few core commands. 

For more in-depth information, visit the wiki: https://github.com/poruski/LightRAT/wiki

## Available LightRAT shells
 - InQuisitor (powershell): Initial payload, designed to be well-rounded
 - Aggress0r (powershell): Lateral movement payload, with brute forcing for smb and psremoting
 - Ascendant (powershell): Privilege escalation payload, with expanded privchecker and password prompt
 
## Upcoming features
 - More shells!
 - Additional upload methods
 - Function to mitigate keyboard interrupts
 - Support for ncat with ssl
 
*DISCLAIMER: This product was developed exclusively and is intended solely for use in sanctioned penetration tests, lab environments, competitions, and other scenarios where ethical hacking has been explicitly permitted by system owners. The author does not condone and will not accept liability for abuse of tools, techniques, or capabilities provided in this repository. 
