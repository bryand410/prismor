// Data Collection Endpoint, custom table, and Data Collection Rule for
// Prismor shadow-agent inventory.
//
//   az deployment group what-if -g <rg> -f main.bicep \
//     -p workspaceName=<workspace> location=<region>
//
// The posting identity needs Monitoring Metrics Publisher on the rule.
// This file was not validated with `az` in CI.
targetScope = 'resourceGroup'

@description('Azure region for the data collection endpoint and rule.')
param location string

@description('Name of the existing Log Analytics workspace backing Sentinel.')
param workspaceName string

var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'RecordId', type: 'string' }
  { name: 'EntityKey', type: 'string' }
  { name: 'GroupId', type: 'string' }
  { name: 'Kind', type: 'string' }
  { name: 'Surface', type: 'string' }
  { name: 'Source', type: 'string' }
  { name: 'Product', type: 'string' }
  { name: 'Vendor', type: 'string' }
  { name: 'Name', type: 'string' }
  { name: 'Version', type: 'string' }
  { name: 'HostId', type: 'string' }
  { name: 'Hostname', type: 'string' }
  { name: 'UserHash', type: 'string' }
  { name: 'TenantId', type: 'string' }
  { name: 'EnvironmentId', type: 'string' }
  { name: 'Managed', type: 'boolean' }
  { name: 'GovernedBy', type: 'string' }
  { name: 'RiskScore', type: 'int' }
  { name: 'RiskLevel', type: 'string' }
  { name: 'RiskSignals', type: 'dynamic' }
  { name: 'Location', type: 'dynamic' }
  { name: 'Attributes', type: 'dynamic' }
  { name: 'RunId', type: 'string' }
  { name: 'ScannerVersion', type: 'string' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: 'dce-prismor-inventory'
  location: location
  properties: {}
}

resource inventoryTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'PrismorAIInventory_CL'
  properties: {
    schema: {
      name: 'PrismorAIInventory_CL'
      columns: columns
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'dcr-prismor-inventory'
  location: location
  dependsOn: [inventoryTable]
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-PrismorAIInventory': {
        columns: columns
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'sentinel'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Custom-PrismorAIInventory']
        destinations: ['sentinel']
        transformKql: 'source'
        outputStream: 'Custom-PrismorAIInventory_CL'
      }
    ]
  }
}

output dataCollectionEndpoint string = dce.properties.logsIngestion.endpoint
output dataCollectionRuleId string = dcr.properties.immutableId
output inventoryStream string = 'Custom-PrismorAIInventory'
