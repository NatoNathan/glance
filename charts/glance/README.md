# Glance Helm chart

Deploys [Glance](https://github.com/NatoNathan/glance) to Kubernetes, exposed through an Ingress or a Gateway API HTTPRoute.

```bash
helm install glance oci://ghcr.io/natonathan/charts/glance --values values.yaml
```

By default the chart uses the `ghcr.io/natonathan/glance` image, which adds OIDC single sign-on. To use the upstream image instead, set `image.repository=glanceapp/glance` and `image.tag` to one of its releases.

## Configuration

Glance's config goes in `config`, either as a map or as a string, and is written to `glance.yml` in a ConfigMap. `server.port` is always set to `containerPort`. The config isn't passed through Helm's `tpl`, so Glance's own template syntax, e.g. in `custom-api` widgets, can be used as is.

```yaml
config:
  pages:
    - name: Home
      columns:
        - size: full
          widgets:
            - type: rss
              feeds:
                - url: https://selfh.st/rss/
```

Additional files, e.g. for `$include`, can be added with `extraConfigFiles`, or you can provide your own ConfigMap containing `glance.yml` with `existingConfigMap`. The pod is restarted when the config changes, set `restartOnConfigChange: false` to rely on Glance's own config reloading instead.

Secrets are referenced from the config through environment variables:

- `secretKey.generate: true` generates a random auth `secret-key`, available as `${GLANCE_SECRET_KEY}`. It's kept across upgrades and not deleted on uninstall, since changing it logs everyone out. Use `secretKey.existingSecret` to provide your own, with a `secret-key` key.
- `secretEnv` creates a Secret with the given environment variables.
- `env` and `envFrom` add environment variables from anywhere else, e.g. an existing Secret.

## Exposing Glance

With an Ingress:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
  hosts:
    - host: glance.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: glance-tls
      hosts:
        - glance.example.com
```

With a Gateway API HTTPRoute:

```yaml
httpRoute:
  enabled: true
  parentRefs:
    - name: gateway
      namespace: gateway-system
      sectionName: https
  hostnames:
    - glance.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
```

Each rule is sent to the Glance service, so `backendRefs` don't need to be set. Rules can use `matches`, `filters` and anything else HTTPRoute rules support.

If Glance is served under a path with `server.base-url`, the Ingress or HTTPRoute has to strip that path before forwarding requests, e.g. with a `URLRewrite` filter.

## Single sign-on (OIDC)

```yaml
secretKey:
  generate: true

envFrom:
  - secretRef:
      name: glance-oidc # contains OIDC_CLIENT_SECRET

persistence:
  enabled: true

config:
  auth:
    secret-key: ${GLANCE_SECRET_KEY}
    oidc:
      issuer-url: https://auth.example.com/application/o/glance/
      client-id: glance
      client-secret: ${OIDC_CLIENT_SECRET}
      redirect-url: https://glance.example.com/auth/oidc/callback
      allowed-groups:
        - glance-users
  pages:
    # ...
```

When `auth.oidc.session-file` isn't set, sessions are stored on the data volume mounted at `persistence.mountPath`. Enable `persistence` so that users stay logged in when the pod is restarted. See the [OIDC docs](../../docs/configuration.md#single-sign-on-oidc) for all options.

Only one replica is supported, and the Deployment uses the `Recreate` strategy, since sessions and login rate limits are kept by the single Glance process.

## Values

See [values.yaml](values.yaml) for all values and their defaults. The most commonly used ones:

| Name | Description | Default |
| ---- | ----------- | ------- |
| `image.repository` | Image repository | `ghcr.io/natonathan/glance` |
| `image.tag` | Image tag | chart `appVersion` |
| `config` | Contents of `glance.yml`, a map or a string | example page |
| `extraConfigFiles` | Additional files next to `glance.yml` | `{}` |
| `existingConfigMap` | Use an existing ConfigMap instead of `config` | `""` |
| `secretKey.generate` | Generate an auth secret-key as `GLANCE_SECRET_KEY` | `false` |
| `secretKey.existingSecret` | Existing Secret with a `secret-key` key | `""` |
| `secretEnv` | Environment variables stored in a chart managed Secret | `{}` |
| `env` / `envFrom` | Additional environment variables | `[]` |
| `ingress.enabled` | Create an Ingress | `false` |
| `httpRoute.enabled` | Create an HTTPRoute | `false` |
| `persistence.enabled` | Store data such as OIDC sessions on a PVC | `false` |
| `persistence.mountPath` | Where the data volume is mounted | `/app/data` |
| `extraVolumes` / `extraVolumeMounts` | Additional volumes, e.g. for `server.assets-path` | `[]` |
| `extraObjects` | Additional manifests, rendered with `tpl` | `[]` |

## Testing

```bash
helm test glance
```
