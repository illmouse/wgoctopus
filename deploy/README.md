# k3s example

These manifests are a conservative starting point, not a production security
review. Build and publish the orchestrator image yourself, then change the
image in `k3s/orchestrator.yaml`. To deploy the optional Telegram bot, publish
its image and change the image in `k3s/bot.yaml`. The single replica and PVC are intentional:
SQLite state must not be shared by multiple pods.

Create the namespace and secret out-of-band; do not commit credentials:

```sh
kubectl create namespace wgoctopus
kubectl -n wgoctopus create secret generic orchestrator \
  --from-literal=WGOCTOPUS_WEB_ADMIN_PASSWORD='use-a-long-unique-password' \
  --from-literal=WGOCTOPUS_API_TOKEN="$(openssl rand -hex 32)"
kubectl apply -f deploy/k3s/
kubectl -n wgoctopus create secret generic wgoctopus-secrets \
  --from-literal=BOT_TOKEN='telegram-bot-token' \
  --from-literal=WGOCTOPUS_API_TOKEN="$(openssl rand -hex 32)"
kubectl apply -f deploy/k3s/bot.yaml # optional bot deployment
kubectl -n wgoctopus port-forward svc/wgoctopus 8080:80
```

Open `http://127.0.0.1:8080/login`. No public ingress is installed by default.
Keep the admin password and API token out of manifests and source control.
Back up `/var/lib/wgoctopus` using your own tested storage procedure before
production use; this example does not configure backups.
