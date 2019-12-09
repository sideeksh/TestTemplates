# policy-based-replication

## summary
Enabling DR at scale using Azure Policy.

### policy-1.0
 - No ADE support (will come as non-compliant though)
 - No Zone support (won't appear)
 - No unmanaged disks (won't appear)
 - Resources that should be precreated
    - Vault RG + vault
    - ASR - Fabrics, Containers, Policy and Mapping
    - Azure - Target RG, Cache SA, Recovery Network
 - Resources deployed
    - Availability Set (only if source VM is in an AvSet)
    - Protected item (only if eligible - current state, OS)
        - Only CacheSA, RecoveryRG added so far. RecoveryDiskTypes NOT present