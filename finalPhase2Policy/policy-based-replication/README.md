# policy-based-replication script

## summary
This script creates all the prerequisite resources for allowing policy based replication at scale. Once the resources are created, the script further deploys a new policy assignment with appropriate parameters.
The following resources are created:
- azure
   - source resource group
      - check if resource group already exists
      - create resource group in source location
   - target resource group
      - check if resource group already exists
      - create resource group in target location
   - cache storage account
      - check if storage account already exists and in the correct location
      - generate name based on vault name and guid
      - create storage account in source location
   - recovery virtual network
      - check if virtual network already exists and in the correct location
      - check to ensure at least 1 subnet exists
      - create virtual network in target location with 1 subnet
- asr
   - vault resource group
      - check if resource group already exists
      - create resource group in target location
   - vault
      - check if vault already exists and not in source location
      - create vault in target location
   - 2 replication fabrics
      - check if fabrics already exist for source and target location
      - create fabrics (asr-a2a-policy-\<location\>)
   - 2 replication protection containers
      - check if protection containers (\<fabric-name\>-container) already exist
      - create protection containers in above format
   - replication policy
      - check if replication already exists
      - create replication policy with appropriate configurations
   - 2 replication protection container mappings (source-> target, target-> source)
      - check if mapping already exists between the containers using the replication policy
      - create mapping
- policy
   - policy definition
      - checking if a policy definition already exists (this is all that should be needed once the policy is published)
      - using policy body and parameters set uploaded on github, create a new policy definition under 'Disaster Recovery'
   - policy assignment
      - checking if any policy assignments already made with the above policy definition and same scope (source resource group).
      - if above shows even 1, the user is prompted regarding this and asked whether they would like to continue or abort.
      - create a new policy assignment with important information in description.

All the important details are written in a file (at script location).
The user is also provided with important URLs and next steps.

## parameters
- name="_subscriptionId_" - Mandatory parameter defining the subscription Id.
- name="_sourceResourceGroupName_" - Mandatory parameter defining the source resource group name. The policy will be deployed at this resource group's scope.
- name="_sourceLocation_" - Mandatory parameter defining the source region.
- name="_targetLocation_" - Mandatory parameter defining the target region.
- name="_vaultResourceGroupName_" - Mandatory parameter defining the vault resource group name.
- name="_vaultName_" - Mandatory parameter defining the vault name.
- name="_msiLocation_" - Mandatory parameter defining the location where the managed services identity is deployed.
- name="_replicationPolicyName_" - Optional parameter defining the replication policy name. Default value used - 24-hours-retention-policy.
- name="_recoveryNetworkName_" - Optional parameter defining the recovery network name. Default value used - \<sourceResourceGroupName\>-vnet-asr.
- name="_targetResourceGroupName_" - Optional parameter defining the target resource group name. Default value used - \<sourceResourceGroupName\>-asr.
- name="_cacheStorageAccountName_" - Optional parameter defining the cache storage account name. Default value used - \<vaultName\> + cacheasr + GUID. This is trimmed down to 24 length.
- name="_cacheStorageAccountSkuName_" - Optional parameter defining the cache storage account SKU name. Default value used - Standard_LRS.
- name="_recoverySubnetName_" - Optional parameter defining a subnet name in case a new recovery network is created. Default value used - default.
- name="_addressPrefix_" - Optional parameter defining the address prefix range in case a new recovery network is created. This address prefix is used by the corresponding recovery subnet as well. Default value used - 10.0.0.0/16.
- name="_pitRetentionInHours_" - Optional parameter defining the recovery point retention in hours in case a new replication policy is created. Default value used - 24.
- name="_appConsistentFrequencyInHours_" - Optional parameter defining the application consistent snapshot frequency in hours, in case a new replication policy is created. Default value used - 24.