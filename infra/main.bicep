@description('Name of the Static Web App')
param name string = 'swa-cms-oauth-shared'

@description('Azure region')
param location string = 'westeurope'

@description('Resource tags')
param tags object = {
  workload: 'websites'
  purpose: 'cms-oauth'
  managedBy: 'IT-CI/cms-oauth'
}

resource swa 'Microsoft.Web/staticSites@2023-12-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {
    buildProperties: {}
  }
}

// Placeholder app settings - real values set post-deploy via `az staticwebapp appsettings set`
// Declared here so the Bicep documents which keys are expected; empty values are overwritten.
// WARNING: Do NOT re-run this Bicep after configuring real values - it will reset them to empty.
resource swaConfig 'Microsoft.Web/staticSites/config@2023-12-01' = {
  parent: swa
  name: 'appsettings'
  properties: {
    GITHUB_CLIENT_ID: ''
    GITHUB_CLIENT_SECRET: ''
    ALLOWED_DOMAINS: ''
    CSRF_SECRET: ''
  }
}

output name string = swa.name
output defaultHostname string = swa.properties.defaultHostname
output resourceId string = swa.id
