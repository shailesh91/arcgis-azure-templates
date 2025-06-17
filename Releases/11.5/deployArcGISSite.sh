#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# -e: immediately exit if any command has a non-zero exit status
# -o: prevents errors in a pipeline from being masked 
# IFS new value is less likely to cause confusing bugs when looping arrays or arguments (e.g. $@)

# Login to Azure 
# Refer to https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-authenticate-service-principal-cli
# for details on non interactive login
az account show 1> /dev/null
if [ $? != 0 ];
then
    az login --tenant '__TENANT_ID_PLACEHOLDER_TEXT__'
fi

# Select the Azure subscription
declare subscriptionId='__SUBSCRIPTION_ID_PLACEHOLDER_TEXT__'

az account set --subscription $subscriptionId

declare storageAccountName='__STORAGE_ACCOUNT_PLACEHOLDER_TEXT__'
declare storageAccountResourceGroupName='__STORAGE_ACCOUNT_RESOURCE_GROUP_NAME_PLACEHOLDER_TEXT__'
declare resourceGroupName='__RESOURCE_GROUP_NAME_PLACEHOLDER_TEXT__'
declare resourceGroupLocation='__RESOURCE_GROUP_LOCATION_PLACEHOLDER_TEXT__'

./deployAzureResourceGroup.sh -i $subscriptionId -g $resourceGroupName -l $resourceGroupLocation -s $storageAccountName  -r $storageAccountResourceGroupName