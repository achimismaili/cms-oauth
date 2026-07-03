# cms-oauth

GitHub OAuth proxy for [Decap CMS](https://decapcms.org) instances on GitHub Pages.

Port of [sveltia-cms-auth](https://github.com/sveltia/sveltia-cms-auth) (MIT) to [Azure Static Web Apps](https://azure.microsoft.com/en-us/products/app-service/static) managed functions.

## Usage

Point your Decap CMS `config.yml` at this proxy:

```yaml
backend:
  name: github
  repo: your-org/your-repo
  branch: main
  base_url: https://<swa-hostname>.azurestaticapps.net
```

The `base_url` is the Azure Static Web Apps URL for this deployed proxy.

## Add a new site

Append the new domain to the `ALLOWED_DOMAINS` app setting (comma-separated glob patterns):

```bash
az staticwebapp appsettings set \
  --name swa-cms-oauth-shared \
  --resource-group rg-websites-shared \
  --setting-names "ALLOWED_DOMAINS=*.ismaili.de,newsite.example.com"
```

Wildcards: `*.ismaili.de` matches `achim.ismaili.de`, `dev.ismaili.de`, etc. but NOT `evilismaili.de`.

## Deployment

**One-time infrastructure provisioning:**
```bash
az deployment group create \
  --resource-group rg-websites-shared \
  --template-file infra/main.bicep
```

**Continuous deployment:** GitHub Actions via `.github/workflows/deploy.yml` — triggered on push to `main`.

## Attribution

This project is a port of [sveltia-cms-auth](https://github.com/sveltia/sveltia-cms-auth) by Sveltia, licensed under MIT. The port adapts the Cloudflare Worker implementation to Azure Functions v3 and improves CSRF state handling (stateless HMAC instead of cookies) for cross-browser compatibility.

## License

MIT
