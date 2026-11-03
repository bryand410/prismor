// Tables, a direct-ingestion DCR, an optional DCE, and the publisher role.
// API versions and output paths are TODO(verify) against the Bicep reference:
// https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/datacollectionrules
// https://learn.microsoft.com/en-us/azure/templates/microsoft.operationalinsights/workspaces/tables
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace (Sentinel-enabled) name')
param workspaceName string

@description('Must equal the workspace region, for example uksouth')
param location string = resourceGroup().location

@description('Create a DCE. Needed for Private Link / AMPLS.')
param useDce bool = false

@description('Object id of the service principal or managed identity that will send')
param senderPrincipalId string

@allowed([
  'ServicePrincipal'
  'Group'
])
param senderPrincipalType string = 'ServicePrincipal'

param namePrefix string = 'prismor'

@description('Interactive retention days for both tables')
param retentionInDays int = 90

@description('Total retention days. TODO(verify) the property name on the table API.')
param totalRetentionInDays int = 365

var eventsTable = 'PrismorAgentEvents_CL'
var invTable = 'PrismorAIInventory_CL'
var eventsStream = 'Custom-PrismorAgentEvents'
var invStream = 'Custom-PrismorAIInventory'
var mmpRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource tEvents 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ws
  name: eventsTable
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    schema: {
      name: eventsTable
      columns: loadJsonContent('schema/agent_events.table.json')
    }
  }
}

resource tInv 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: ws
  name: invTable
  properties: {
    plan: 'Analytics'
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    schema: {
      name: invTable
      columns: loadJsonContent('schema/ai_inventory.table.json')
    }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = if (useDce) {
  name: '${namePrefix}-dce'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${namePrefix}-dcr'
  location: location
  // TODO(verify): kind Direct together with dataCollectionEndpointId.
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: useDce ? dce.id : null
    streamDeclarations: {
      '${eventsStream}': {
        columns: loadJsonContent('schema/agent_events.stream.json')
      }
      '${invStream}': {
        columns: loadJsonContent('schema/ai_inventory.stream.json')
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'la'
          workspaceResourceId: ws.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          eventsStream
        ]
        destinations: [
          'la'
        ]
        outputStream: 'Custom-${eventsTable}'
        transformKql: 'source | extend TimeGenerated = todatetime(EventTime)'
      }
      {
        streams: [
          invStream
        ]
        destinations: [
          'la'
        ]
        outputStream: 'Custom-${invTable}'
        transformKql: 'source | extend TimeGenerated = todatetime(ObservedAt)'
      }
    ]
  }
  dependsOn: [
    tEvents
    tInv
  ]
}

resource mmp 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, senderPrincipalId, mmpRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', mmpRoleId)
    principalId: senderPrincipalId
    principalType: senderPrincipalType
  }
}

output dcrImmutableId string = dcr.properties.immutableId
// TODO(verify): logsIngestion vs endpoints.logsIngestion on DCR and DCE.
output logsIngestionEndpoint string = useDce ? dce!.properties.logsIngestion.endpoint : dcr.properties.endpoints.logsIngestion
output eventsStream string = eventsStream
output inventoryStream string = invStream
