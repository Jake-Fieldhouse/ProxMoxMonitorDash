# ProxMoxMonitorDash

## Configuration

`Proxmox.sh` reads its zone, cluster name and Tailscale API key from
`/etc/hosted-dns.conf` if the file exists. You may also set the following
environment variables before running the script:

```bash
export ZONE=my.domain
export CLUSTER_NAME=mycluster
export TS_API_KEY=tskey-XXXXX
```

If `/etc/hosted-dns.conf` does not exist it will be created using the values
from these variables (or the script defaults) on first run.
