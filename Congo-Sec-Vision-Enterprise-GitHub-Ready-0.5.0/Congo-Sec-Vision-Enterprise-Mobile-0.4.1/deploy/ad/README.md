# Active Directory / GPO rollout
Run `Install-CongoSecVision-GPO.ps1` from a domain-joined admin workstation with RSAT, GroupPolicy and ActiveDirectory modules.

The script creates/links a GPO, copies the endpoint agent and startup script to SYSVOL, and configures a startup script. Client endpoints need Python 3 + pip preinstalled and network access to the SOC API over HTTPS.

Security caveat: the bootstrap enrollment token in SYSVOL is readable by authenticated domain users by default. For production, use a dedicated short-lived/rotatable enrollment secret and harden SYSVOL ACLs or replace bootstrap with machine-certificate enrollment. Test against a pilot OU first. The script does not silently install software on devices outside the linked OU.
