# RallyUp Log Aggregation — Loki + Alloy + Grafana

Ships every Docker container's stdout/stderr to Loki (14-day retention,
`retention_period: 336h` — disk is ~80% full, do not raise this without
checking `df -h`). Grafana Alloy tails the Docker daemon and labels each
stream with `container=<name>`. Grafana gets a provisioned Loki datasource
(uid `loki`) and the `RallyUp · Logs` dashboard.

## Files in this package

| File | Purpose | Server destination |
|---|---|---|
| `loki.yml` | Loki 3.x single-binary config | `~/apps/loki/loki.yml` |
| `config.alloy` | Alloy log-shipping pipeline | `~/apps/alloy/config.alloy` |
| `grafana-provisioning/datasources/loki.yml` | Loki datasource | `~/apps/grafana/provisioning/datasources/loki.yml` |
| `grafana-provisioning/dashboards/rallyup.yml` | Dashboard provider | `~/apps/grafana/provisioning/dashboards/rallyup.yml` |
| `../dashboards/rallyup-logs.json` | Logs dashboard | `~/apps/grafana/provisioning/dashboards/json/rallyup-logs.json` |
| `compose-snippet.yml` | Services to merge into master compose | (reference only) |

## 1. Create directories on the server

```bash
ssh server 'mkdir -p ~/apps/loki ~/apps/alloy/data ~/apps/grafana/provisioning/datasources ~/apps/grafana/provisioning/dashboards/json'
```

## 2. Copy configs

Run from the repo root (`badminton-be-rust/`):

```bash
scp deploy/logs/loki.yml                                        server:~/apps/loki/loki.yml
scp deploy/logs/config.alloy                                    server:~/apps/alloy/config.alloy
scp deploy/logs/grafana-provisioning/datasources/loki.yml       server:~/apps/grafana/provisioning/datasources/loki.yml
scp deploy/logs/grafana-provisioning/dashboards/rallyup.yml     server:~/apps/grafana/provisioning/dashboards/rallyup.yml
scp deploy/dashboards/rallyup-logs.json                         server:~/apps/grafana/provisioning/dashboards/json/rallyup-logs.json
```

## 3. Edit the master docker-compose.yml

On the server, merge the `loki` and `alloy` services from
`compose-snippet.yml` into the master compose file, and:

1. Declare the named volume at top level:

   ```yaml
   volumes:
     lokidata: {}
   ```

2. Add the provisioning mount to the existing `grafana` service:

   ```yaml
   volumes:
     - ~/apps/grafana/provisioning:/etc/grafana/provisioning
   ```

Both new services join the existing `appnetwork` network with
`restart: always`.

## 4. Bring it up

```bash
docker compose up -d loki alloy
docker compose up -d --force-recreate grafana   # picks up provisioning mount
```

## 5. Verify

Loki ready (returns `ready` — may take ~15s after start while the ring
settles):

```bash
docker exec loki wget -qO- http://localhost:3100/ready
# or, from another container on appnetwork:
docker exec alloy sh -c 'wget -qO- http://loki:3100/ready'
```

Labels arriving (should list `container`):

```bash
docker exec loki wget -qO- 'http://localhost:3100/loki/api/v1/labels'
```

LogQL query check — recent backend log lines:

```bash
docker exec loki wget -qO- \
  'http://localhost:3100/loki/api/v1/query_range?query={container="badminton-be-rust"}&limit=5' \
  | head -c 2000
```

Alloy health (no errors shipping):

```bash
docker logs alloy --tail 50
```

Grafana: open Grafana → Dashboards → `RallyUp · Logs` (uid
`rallyup-logs`). Datasource `Loki` (uid `loki`) should show under
Connections → Data sources as non-editable.

## Troubleshooting

- `/ready` says `Ingester not ready`: normal for the first ~15s; retry.
- No logs at all: check Alloy can reach the socket
  (`docker exec alloy ls /var/run/docker.sock`) and that the compose
  mounted it read-only.
- Disk pressure: retention is enforced by the compactor
  (`retention_enabled: true`, `delete_request_store: filesystem`); data
  lives in the `lokidata` named volume. Check size with
  `docker system df -v | grep lokidata`.
