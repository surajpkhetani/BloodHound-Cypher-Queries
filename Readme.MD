User to User permissions
```
MATCH p=(m:User {admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:User) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
MATCH p=(m:User )-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:User) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A"  AND NOT m.name contains "SCCM" AND m.domain contains "INTERNAL" RETURN m.name,r,n.name
```


User to Group permissions
```
MATCH p=(m:User {admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Group) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
MATCH p=(m:User{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Group) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A"  AND NOT m.name contains "SCCM"  AND NOT m.name contains "MSOL" AND m.domain contains "INTERNAL" RETURN p
MATCH p=(m:User{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|Owns|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Group) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A"  AND NOT m.name contains "SCCM"  AND m.domain contains "INTERNAL" RETURN p
```

User to Computer permissions
```
MATCH p=(m:User {admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Computer) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
MATCH p=(m:User )-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|Owns|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Computer) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A"  AND NOT m.name contains "SCCM"  AND m.domain contains "INTERNAL" RETURN p
MATCH p=(m:User{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|Owns|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Computer) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A"  AND NOT m.name contains "SCCM"  AND m.domain contains "INTERNAL" RETURN p
```

User to Domain
```
MATCH p=(m:User {admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Domain) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
```

User to GPO
```
MATCH p=(m:User )-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:GPO) WHERE NOT m.name contains "SVC_" AND NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND NOT m.name contains "-A" RETURN p
```

Group to User
```
MATCH p=(m:Group{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:User) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
```

Group to Group
```
MATCH p=(m:Group{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Group) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
```

Group to Computer
```
MATCH p=(m:Group{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Computer) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
```
Group to Domain
```
MATCH p=(m:Group{admincount:FALSE})-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:Domain) WHERE NOT m.name contains "ADMINISTRATOR" AND NOT m.name contains "ADMIN" AND m.domain contains "DOMAIN" RETURN p LIMIT 1000
```
Group to GPO
```
MATCH p=(m:Group )-[r:AdminTo|ForceChangePassword|AddMembers|AddSelf|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin|AllowedToDelegate|DCSync|GetChanges|GetChangesAll|GenericAll|WriteDACL|GenericWrite|WriteOwner|WriteSPN|Owns|AddKeyCredentialLink|ReadLAPSPassword|ReadGMSAPassword|AllExtendedRights|GpLink|AllowedToAct|AddAllowedToAct|TrustedBy|SyncLAPSPasword|AZTenant|AZUser|AZGroup|AZApp|AZSubscription|AZResourceGroup|AZVM|AZDevice|AZServicePrincipal]->(n:GPO) WHERE NOT m.name contains "ADMIN" AND NOT m.name contains "OPERATORS" AND NOT m.name contains "EXCHANGE" AND NOT m.name contains "MANAGEMENT" AND NOT m.name contains "ACTIVEDIRECTORY" AND NOT m.name contains "ACCESS" AND NOT m.name contains "HELPDESK" AND NOT m.name contains "JOINING" AND NOT m.name contains "REMOTE" AND NOT m.name contains "SIGNAGE" RETURN p
```
