# Basilica Telemetry Deployment

This project deploys a complete telemetry stack for Basilica validator monitoring, including Prometheus, Loki, Grafana, and NGINX reverse proxy.

## Quick Start

1. **Configure your inventory:**

   ```bash
   cp inventory.example inventory
   # Edit inventory with your server details
   ```

2. **Configure variables:**

   ```bash
   cp group_vars/all.yml.example group_vars/all.yml
   # Edit group_vars/all.yml with your settings
   ```

3. **Deploy the stack:**

   ```bash
   ansible-playbook -i inventory playbook.yml
   ```

## Features

### Complete Telemetry Stack

- **Prometheus**: Metrics collection and storage with 30-day retention
- **Loki**: Log aggregation with structured log processing
- **Grafana**: Pre-configured dashboards for validator metrics and logs
- **Alloy**: Log and metrics collection agent
- **Node Exporter**: System metrics collection
- **Alertmanager**: Alert management and notifications

### NGINX Reverse Proxy

- **Grafana**: Available on port 80/443 (main interface)
- **Prometheus**: Available on port 8080/8443
- **Loki**: Available on port 8081/8444
- SSL termination with self-signed certificates
- Security headers and rate limiting
- Health check endpoints

### Production Ready

- Docker Compose orchestration
- Persistent volume management
- Network isolation and security
- Comprehensive health checks
- Idempotent deployments
- Zero-downtime updates

## Architecture

```text
         ┌─────────────────┐
         │   Basilica      │
         │   Telemetry     │
         │   Deployment    │
         └─────────────────┘
                 │
                 ▼
         ┌─────────────────┐
         │  Docker Compose │
         └─────────────────┘
                 │
                 ▼
         ┌──────────────────┼─────────────────────┐
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     NGINX       │    │    Grafana      │    │   Prometheus    │
│   (Reverse      │    │   (Dashboard)   │    │   (Metrics)     │
│    Proxy)       │    │     :3000       │    │     :9090       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
         │      Loki       │    │     Alloy       │    │ Node Exporter   │
         │   (Logs)        │    │ (Collection)    │    │   (System)      │
         │     :3100       │    │    :12345       │    │     :9100       │
         └─────────────────┘    └─────────────────┘    └─────────────────┘
                                         │
                                 ┌─────────────────┐
                                 │  Validator      │
                                 │  Container      │
                                 │   (Metrics)     │
                                 └─────────────────┘
```

## Configuration

### Required Variables

Edit `group_vars/all.yml`:

```yaml
# Basic configuration
basilica_domain: "your-domain.com"
basilica_telemetry_dir: "/opt/basilica/telemetry"

# Service ports (defaults shown)
prometheus_port: 9090
loki_port: 3100
grafana_port: 3000

# NGINX settings
nginx_enabled: true
nginx_ssl_enabled: false  # Set to true for production
```

### Optional Configuration

#### SSL Configuration

```yaml
nginx_ssl_enabled: true
nginx_cert_country: "US"
nginx_cert_state: "California"
nginx_cert_locality: "San Francisco"
nginx_cert_organization: "Your Organization"
```

#### Resource Limits

```yaml
prometheus_retention_time: "90d"
prometheus_retention_size: "50GB"
nginx_worker_processes: 4
nginx_worker_connections: 8192
```

#### Security Settings

```yaml
nginx_metrics_allowed_cidrs:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
```

### Sensitive Variables

Use Ansible Vault for sensitive data:

```bash
# Create encrypted vault file
ansible-vault create group_vars/vault.yml

# Add sensitive variables
vault_grafana_admin_password: "your_secure_password"
vault_grafana_secret_key: "your_secret_key"
```

Reference in `group_vars/all.yml`:

```yaml
grafana_admin_password: "{{ vault_grafana_admin_password }}"
```

## Deployment Commands

### Standard Deployment

```bash
ansible-playbook -i inventory playbook.yml
```

### Check Mode (Dry Run)

```bash
ansible-playbook -i inventory playbook.yml --check
```

### Force Recreation

```bash
ansible-playbook -i inventory playbook.yml -e "basilica_force_recreate=true"
```

### Deploy Specific Components

```bash
# Docker only
ansible-playbook -i inventory playbook.yml --tags docker

# Telemetry services only
ansible-playbook -i inventory playbook.yml --tags telemetry

# NGINX only
ansible-playbook -i inventory playbook.yml --tags nginx
```

### Using Vault

```bash
# Prompt for vault password
ansible-playbook -i inventory playbook.yml --ask-vault-pass

# Use vault password file
ansible-playbook -i inventory playbook.yml --vault-password-file .vault_pass
```

## Post-Deployment

### Access URLs

After successful deployment:

- **Grafana**: <http://your-server/>
  - Username: `admin`
  - Password: `basilica_admin` (or your configured password)

- **Prometheus**: <http://your-server:8080/>
- **Loki**: <http://your-server:8081/>
- **Direct access**: Use original ports (3000, 9090, 3100)

### Verify Deployment

1. **Check service health:**

   ```bash
   curl http://your-server/api/health  # Grafana
   curl http://your-server:8080/-/healthy  # Prometheus
   curl http://your-server:8081/ready  # Loki
   ```

2. **Check Docker containers:**

   ```bash
   docker ps | grep basilica
   ```

3. **Check logs:**

   ```bash
   docker logs basilica-grafana
   docker logs basilica-prometheus
   docker logs basilica-loki
   ```

### Validator Integration

Ensure your validator:

1. **Exposes metrics** on port 9090
2. **Writes logs** to `/var/log/basilica/`
3. **Runs on** the `basilica_network` Docker network

Example validator compose snippet:

```yaml
networks:
  - basilica_network

ports:
  - "9090:9090"  # Metrics port

volumes:
  - /var/log/basilica:/var/log/basilica:rw
```

## Troubleshooting

### Common Issues

1. **Port conflicts:**

   ```bash
   netstat -tulpn | grep -E "(3000|9090|3100)"
   ```

2. **Docker network issues:**

   ```bash
   docker network ls
   docker network inspect basilica_network
   ```

3. **Permission issues:**

   ```bash
   ls -la /opt/basilica/telemetry/
   ls -la /var/log/basilica/
   ```

4. **NGINX configuration:**

   ```bash
   nginx -t
   systemctl status nginx
   ```

### Logs and Debugging

1. **Ansible verbose output:**

   ```bash
   ansible-playbook -i inventory playbook.yml -vvv
   ```

2. **Service logs:**

   ```bash
   docker logs basilica-grafana
   docker logs basilica-prometheus
   docker logs basilica-loki
   ```

3. **NGINX logs:**

   ```bash
   tail -f /var/log/nginx/error.log
   tail -f /var/log/nginx/basilica-grafana.access.log
   ```

### Recovery

1. **Restart services:**

   ```bash
   cd /opt/basilica/telemetry
   docker compose -f docker-compose.prod.yml restart
   ```

2. **Recreate stack:**

   ```bash
   ansible-playbook -i inventory playbook.yml -e "basilica_force_recreate=true"
   ```

3. **Reset volumes:**

   ```bash
   docker compose -f docker-compose.prod.yml down -v
   ansible-playbook -i inventory playbook.yml
   ```

## Advanced Configuration

### Custom Dashboards

Add custom Grafana dashboards:

1. Place JSON files in `roles/basilica-telemetry/files/grafana/dashboards/`
2. Re-run the playbook

### Custom Alerting Rules

Add Prometheus alerting rules:

1. Create `.yml` files in `roles/basilica-telemetry/files/rules/`
2. Re-run the playbook

### External Storage

For production, consider external storage:

```yaml
# Use external Loki storage
loki_storage_type: "s3"
loki_s3_bucket: "your-loki-bucket"
loki_s3_endpoint: "https://s3.amazonaws.com"
```

## Security Considerations

1. **Change default passwords**
2. **Enable SSL in production**
3. **Restrict metrics access**
4. **Use Ansible Vault for secrets**
5. **Configure firewall rules**
6. **Regular security updates**

## Maintenance

### Updates

1. **Update service versions** in `group_vars/all.yml`
2. **Re-run playbook** to update containers
3. **Verify health** after updates

### Backups

Backup persistent data:

```bash
docker run --rm -v prometheus_data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-backup.tar.gz /data
docker run --rm -v loki_data:/data -v $(pwd):/backup alpine tar czf /backup/loki-backup.tar.gz /data
docker run --rm -v grafana_data:/data -v $(pwd):/backup alpine tar czf /backup/grafana-backup.tar.gz /data
```
