// Analytics rules, saved searches, and the workbook.
// API versions are TODO(verify):
// alertRules e.g. 2023-02-01, savedSearches, workbooks 2022-04-01.
// The checked-in document is content.generated.json, produced by tools/build_content.py.
targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace name')
param workspaceName string

param location string = resourceGroup().location

resource ws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

var content = loadJsonContent('content.generated.json')

// TODO(verify): Microsoft.SecurityInsights/alertRules API version.
resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: guid(ws.id, 'prismor-ai-posture')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'Prismor AI posture'
    sourceId: ws.id
    category: 'sentinel'
    serializedData: loadTextContent('../workbooks/prismor-ai-posture.workbook.json')
  }
}

output contentVersion string = content.contentVersion
output workbookName string = workbook.name
