#!/usr/bin/env bash
# Build a known-bad + known-good IaC corpus inside the scanner container.
set -e
R=/tmp/iac
rm -rf "$R"; mkdir -p "$R/bad" "$R/good"

# ── BAD Dockerfile ──────────────────────────────────────────────────────────
cat > "$R/bad/Dockerfile" <<'EOF'
FROM ubuntu:latest
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEYbadhardcoded
ADD https://example.com/app.tar.gz /app/
RUN apt-get update && apt-get install -y curl
EXPOSE 22
CMD ["/app/run"]
EOF

# ── GOOD Dockerfile ─────────────────────────────────────────────────────────
cat > "$R/good/Dockerfile" <<'EOF'
FROM ubuntu:22.04
RUN useradd -r -u 10001 appuser
COPY app /app/
USER appuser
HEALTHCHECK CMD ["/app/health"]
CMD ["/app/run"]
EOF

# ── BAD Terraform (valid HCL) ───────────────────────────────────────────────
cat > "$R/bad/main.tf" <<'EOF'
resource "aws_s3_bucket" "b" {
  bucket = "my-bad-bucket"
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "open" {
  name = "open-sg"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  allocated_storage   = 10
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  storage_encrypted   = false
  publicly_accessible = true
}
EOF

# ── GOOD Terraform (valid HCL) ──────────────────────────────────────────────
cat > "$R/good/main.tf" <<'EOF'
resource "aws_s3_bucket" "b" {
  bucket = "my-good-bucket"
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "k" {
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = aws_s3_bucket.b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.k.arn
    }
  }
}

resource "aws_db_instance" "db" {
  allocated_storage       = 10
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.k.arn
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
  iam_database_authentication_enabled = true
}
EOF

# ── BAD Kubernetes ──────────────────────────────────────────────────────────
cat > "$R/bad/deploy.yaml" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          securityContext:
            privileged: true
            runAsNonRoot: false
            allowPrivilegeEscalation: true
          volumeMounts:
            - name: h
              mountPath: /host
      volumes:
        - name: h
          hostPath:
            path: /
EOF

# ── GOOD Kubernetes (fully hardened) ────────────────────────────────────────
cat > "$R/good/deploy.yaml" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      automountServiceAccountToken: false
      containers:
        - name: app
          image: myapp:1.2.3
          securityContext:
            privileged: false
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
EOF

# ── BAD docker-compose ──────────────────────────────────────────────────────
cat > "$R/bad/docker-compose.yml" <<'EOF'
version: "3"
services:
  web:
    image: nginx:latest
    privileged: true
    ports:
      - "0.0.0.0:80:80"
    cap_add:
      - SYS_ADMIN
EOF

echo "IaC corpus rebuilt (valid HCL, hardened good files):"
find "$R" -type f | sort
