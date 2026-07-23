# AWS IAM Authentication Setup

Guide for configuring MobSF queue worker with AWS IAM authentication for MemoryDB and RDS.

## Overview

When `NODE_ENV=dev`, `NODE_ENV=stage`, or `NODE_ENV=prod`, MobSF automatically uses IAM authentication instead of passwords:

- **MemoryDB/Redis**: IAM tokens generated every 15 minutes
- **RDS/PostgreSQL**: IAM tokens with 10-minute connection lifetime

## Prerequisites

1. **boto3** installed:

   ```bash
   poetry add boto3
   # or
   pip install boto3
   ```

2. **AWS credentials** available (IAM role or AWS CLI):
   - ECS Task Role (recommended for production)
   - EC2 Instance Profile
   - AWS CLI credentials (`~/.aws/credentials`)

## MemoryDB Configuration

### 1. Enable IAM Auth on MemoryDB Cluster

```bash
aws memorydb update-cluster \
  --cluster-name my-cluster \
  --iam-auth-enabled
```

### 2. Create IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "memorydb:Connect",
      "Resource": "arn:aws:memorydb:us-east-1:123456789012:cluster/my-cluster"
    }
  ]
}
```

### 3. Attach Policy to IAM Role

Attach the policy to your ECS Task Role or EC2 Instance Profile.

### 4. Environment Variables

```bash
NODE_ENV=prod
AWS_REGION=us-east-1
MEMORYDB_CLUSTER_NAME=my-cluster
VALKEY_HOST=clustercfg.my-cluster.xxxxxx.memorydb.us-east-1.amazonaws.com
VALKEY_PORT=6379
VALKEY_USERNAME=default
# VALKEY_PASSWORD not needed with IAM auth
```

## RDS PostgreSQL Configuration

### 1. Enable IAM Auth on RDS Instance

```bash
aws rds modify-db-instance \
  --db-instance-identifier my-db \
  --enable-iam-database-authentication \
  --apply-immediately
```

### 2. Create Database User with IAM Auth

```sql
-- Connect as master user
CREATE USER iam_user;
GRANT rds_iam TO iam_user;
GRANT ALL PRIVILEGES ON DATABASE mobsf TO iam_user;
```

### 3. Create IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-XXXXX/iam_user"
    }
  ]
}
```

**Note**: The resource ARN format is:

```
arn:aws:rds-db:REGION:ACCOUNT:dbuser:DBI-RESOURCE-ID/DB-USERNAME
```

Find `DBI-RESOURCE-ID` with:

```bash
aws rds describe-db-instances \
  --db-instance-identifier my-db \
  --query 'DBInstances[0].DbiResourceId' \
  --output text
```

### 4. Environment Variables

```bash
NODE_ENV=prod
AWS_REGION=us-east-1
POSTGRES_HOST=my-db.xxx.rds.amazonaws.com
POSTGRES_PORT=5432
POSTGRES_USER=iam_user
POSTGRES_DB=mobsf
# POSTGRES_PASSWORD not needed with IAM auth
```

## How It Works

### Token Lifecycle

- **Generation**: Tokens generated on-demand via boto3 SDK
- **Validity**: 15 minutes for both MemoryDB and RDS
- **Refresh**:
  - MemoryDB: Worker auto-restarts on auth errors
  - RDS: Connection pool expires after 10 min (before token expires)

### Worker Behavior

1. **Startup**: Generate initial token
2. **Normal operation**: Process jobs
3. **Token expiration** (~15 min):
   - MemoryDB: Worker catches `AuthenticationError`, restarts with new token
   - RDS: Django closes connections after 10 min, new connections get fresh token
4. **Automatic recovery**: No manual intervention needed

### Publish Retry Logic

When publishing results to MemoryDB, `_publish()` automatically:

1. Attempts to publish payload
2. On `AuthenticationError`: refreshes token and retries (max 2 attempts)
3. Logs warnings on auth errors, errors on exhausted retries

## Testing IAM Auth

### Local Test (with AWS credentials)

```bash
# Set AWS credentials
export AWS_PROFILE=my-profile
# or
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=yyy

# Test with prod mode
NODE_ENV=prod python manage.py queue_worker
```

You should see:

```
Using IAM authentication for MemoryDB (NODE_ENV=prod)
Using IAM authentication for RDS (NODE_ENV=prod)
Worker listening. Press Ctrl+C to stop.
```

### Verify Token Generation

```python
from mobsf.queue_integration.aws_auth import get_memorydb_auth_token, get_rds_auth_token

# Test MemoryDB token
token = get_memorydb_auth_token()
print(f"MemoryDB token: {token[:50]}...")

# Test RDS token
token = get_rds_auth_token()
print(f"RDS token: {token[:50]}...")
```

## Troubleshooting

### "NoCredentialsError: Unable to locate credentials"

- Ensure IAM role is attached to ECS task or EC2 instance
- Or configure AWS CLI: `aws configure`
- Check `AWS_REGION` is set

### "MEMORYDB_CLUSTER_NAME environment variable is required"

- Set `MEMORYDB_CLUSTER_NAME=your-cluster-name`

### "POSTGRES_HOST and POSTGRES_USER environment variables are required"

- Ensure both variables are set in environment

### Token expires too quickly

- Normal behavior: tokens valid 15 minutes
- Worker auto-restarts on expiration
- Check logs for "Restarting worker" messages

### PostgreSQL "password authentication failed"

- Verify IAM auth is enabled on RDS instance
- Verify database user has `rds_iam` role
- Check IAM policy resource ARN matches DbiResourceId
- Verify SSL is enabled (required for IAM auth)

## Security Best Practices

1. **Use IAM roles** instead of access keys in production
2. **Restrict IAM policies** to specific clusters/databases
3. **Enable CloudTrail** to audit authentication attempts
4. **Use VPC security groups** to restrict network access
5. **Never commit credentials** to git (`.env` should be in `.gitignore`)

## Cost Implications

- **MemoryDB**: IAM auth has no additional cost
- **RDS**: IAM auth has no additional cost
- **boto3 calls**: Free tier covers token generation (minimal API calls)

## Migration from Password to IAM Auth

1. Test IAM auth in staging environment
2. Update environment variables (remove passwords, add AWS config)
3. Set `NODE_ENV=prod`
4. Deploy and verify worker connects successfully
5. Monitor logs for auth errors
6. (Optional) Rotate and remove old passwords from secrets manager
