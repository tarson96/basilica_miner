# Basilica Telemetry Stack

This directory contains the complete telemetry stack for the Basilica validator, including Prometheus, Loki, Grafana, and Alloy for comprehensive metrics collection, log aggregation, and visualization.

## Components

- **Prometheus**: Metrics collection and storage
- **Loki**: Log aggregation and storage
- **Grafana**: Visualization and dashboards
- **Alloy**: Log and metrics collection agent
- **Node Exporter**: System metrics collection
- **Alertmanager**: Alert management and notifications

## Deployment Options

### Option 1: Docker Compose (Local Development)

1. **Start the telemetry stack:**

   ```bash
   docker-compose -f compose.prod.yml up -d
   ```

2. **Access the services:**
   - Grafana: <http://localhost:3000> (admin/basilica_admin)
   - Prometheus: <http://localhost:9090>
   - Loki: <http://localhost:3100>
   - Alertmanager: <http://localhost:9093>

### Option 2: Ansible Production Deployment

For production deployment with NGINX reverse proxy and SSL:

```bash
cd ansible
./deploy.sh
```

**Production URLs:**

- Grafana: <https://basilica-grafana.tplr.ai>
- Prometheus: <https://basilica-telemetry.tplr.ai:8080>
- Loki: <https://basilica-logs.tplr.ai>

## Configuration Files

### Prometheus (`prometheus.yml`)

- Scrapes metrics from validator on port 9090
- Collects system metrics via node-exporter
- Stores metrics with 30-day retention
- Includes alerting rules for validator health

### Loki (`loki.yml`)

- Configured for single-node deployment
- File-based storage with 7-day retention
- Optimized for validator log ingestion

### Grafana

- **Configuration**: `grafana/grafana.ini`
- **Dashboards**: `grafana/dashboards/`
  - `basilica_validator_overview.json`: Main validator metrics dashboard
  - `basilica_validator_logs.json`: Log analysis dashboard
- **Provisioning**: Automatic datasource and dashboard provisioning

## Metrics Collected

The validator exposes comprehensive metrics on port 9090:

- **Validation Operations**:
  - `basilica_validator_validations_total`
  - `basilica_validator_validation_duration_seconds`
  - `basilica_validator_validation_score`
  - `basilica_validator_validation_errors_total`

- **SSH Operations**:
  - `basilica_validator_ssh_connections_total`
  - `basilica_validator_ssh_connection_duration_seconds`
  - `basilica_validator_ssh_failures_total`
  - `basilica_validator_ssh_active_connections`

- **System Resources**:
  - `basilica_validator_cpu_usage_percent`
  - `basilica_validator_memory_usage_bytes`
  - `basilica_validator_disk_usage_bytes`

- **Database Operations**:
  - `basilica_validator_database_operations_total`
  - `basilica_validator_database_query_duration_seconds`
  - `basilica_validator_database_errors_total`

- **Business Metrics**:
  - `basilica_validator_executor_health_status`
  - `basilica_validator_consensus_weight_sets_total`
  - `basilica_validator_verification_session_duration_seconds`

## Log Collection

Alloy collects logs from multiple sources:

1. **Docker Container Logs**: Direct collection from validator container
2. **File-based Logs**: Collection from `/var/log/basilica/` directory
3. **Log Processing**: Automatic parsing and labeling

## Alerting

Prometheus alerting rules are configured for:

- High validation error rates
- SSH connection failures
- High CPU/memory usage
- Low disk space
- Database connection issues
- Executor health problems
- Slow validation operations

## Network Configuration

The stack uses two networks:

- `basilica_telemetry`: Internal telemetry network
- `basilica_network`: External network to connect with validator

## Data Persistence

All data is persisted using Docker volumes:

- `prometheus_data`: Metrics storage
- `loki_data`: Log storage
- `grafana_data`: Grafana configuration and dashboards
- `alertmanager_data`: Alert state storage

## Production Considerations

1. **Security**: Default passwords should be changed
2. **Storage**: Monitor disk usage for metrics and logs
3. **Networking**: Configure proper firewall rules
4. **Backup**: Regular backup of persistent volumes
5. **Monitoring**: Monitor the monitoring stack itself

## Integration with Validator

The validator must be configured to:

1. Expose metrics on port 9090
2. Write logs to `/var/log/basilica/`
3. Run on the `basilica_network` Docker network

## Ansible Deployment

For production deployment, use the Ansible automation in the `ansible/` directory:

```bash
cd ansible
ansible-playbook -i inventory playbook.yml
```

### Features

- Automated Docker installation and configuration
- NGINX reverse proxy with SSL certificates
- Firewall configuration
- Service health validation
- Certificate rotation
- Production-ready security settings

### Configuration

- Edit `ansible/inventory` with your server details
- Modify `ansible/group_vars/all.yml` for customization
- Use `ansible/group_vars/vault.yml` for sensitive data

## Troubleshooting

### Common Issues

1. **Metrics not appearing**: Check validator metrics endpoint
2. **Logs not collected**: Verify log file permissions and paths
3. **Dashboards not loading**: Check Grafana datasource configuration
4. **Alerts not firing**: Verify Prometheus rule evaluation

### Health Checks

All services include health checks:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Log Analysis

View service logs:

```bash
docker logs basilica-prometheus
docker logs basilica-loki
docker logs basilica-grafana
```
