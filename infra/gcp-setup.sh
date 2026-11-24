#!/usr/bin/env bash
set -euo pipefail

PROJECT_ID="${1:-${GCP_PROJECT_ID:-}}"
REGION="${GCP_REGION:-asia-south1}"
SQL_INSTANCE="${CLOUD_SQL_INSTANCE:-vigidock-postgres}"
SQL_DATABASE="${CLOUD_SQL_DATABASE:-vigidock}"
SQL_USER="${CLOUD_SQL_USER:-vigidock}"
ARTIFACT_REPO="${ARTIFACT_REGISTRY_REPO:-vigidock}"
BUCKET="${GCS_REPORT_BUCKET:-}"
SERVICE_ACCOUNT="${VIGIDOCK_SERVICE_ACCOUNT:-vigidock-runtime}"
SECRET="${GEMINI_SECRET_NAME:-gemini-api-key}"

if [[ -z "$PROJECT_ID" ]]; then echo "Set GCP_PROJECT_ID or pass project ID as argument" >&2; exit 2; fi
if [[ -z "$BUCKET" ]]; then BUCKET="${PROJECT_ID}-vigidock-reports"; fi
gcloud config set project "$PROJECT_ID" >/dev/null
for api in run.googleapis.com sqladmin.googleapis.com artifactregistry.googleapis.com container.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com storage.googleapis.com; do
  gcloud services enable "$api" --project "$PROJECT_ID"
done
if ! gcloud artifacts repositories describe "$ARTIFACT_REPO" --location "$REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$ARTIFACT_REPO" --repository-format=docker --location="$REGION" --description="VigiDock container images"
fi
if ! gcloud sql instances describe "$SQL_INSTANCE" >/dev/null 2>&1; then
  gcloud sql instances create "$SQL_INSTANCE" --database-version=POSTGRES_15 --region="$REGION" --tier=db-f1-micro --storage-type=SSD --storage-size=10 --assign-ip
fi
if ! gcloud sql databases describe "$SQL_DATABASE" --instance="$SQL_INSTANCE" >/dev/null 2>&1; then gcloud sql databases create "$SQL_DATABASE" --instance="$SQL_INSTANCE"; fi
if ! gcloud sql users list --instance="$SQL_INSTANCE" --format='value(name)' | grep -Fxq "$SQL_USER"; then
  if [[ -z "${CLOUD_SQL_PASSWORD:-}" ]]; then echo "Set CLOUD_SQL_PASSWORD to create the database user" >&2; exit 2; fi
  gcloud sql users create "$SQL_USER" --instance="$SQL_INSTANCE" --password="$CLOUD_SQL_PASSWORD"
fi
if ! gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1; then gcloud storage buckets create "gs://$BUCKET" --location="$REGION" --uniform-bucket-level-access; fi
if ! gcloud secrets describe "$SECRET" >/dev/null 2>&1; then gcloud secrets create "$SECRET" --replication-policy=automatic; fi
if ! gcloud iam service-accounts describe "$SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SERVICE_ACCOUNT" --display-name="VigiDock Cloud runtime"
fi
SA="$SERVICE_ACCOUNT@$PROJECT_ID.iam.gserviceaccount.com"
for role in roles/cloudsql.client roles/artifactregistry.reader roles/container.developer roles/secretmanager.secretAccessor; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:$SA" --role="$role" --condition=None >/dev/null
done
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member="serviceAccount:$SA" --role=roles/storage.objectAdmin >/dev/null
cat <<OUT
Provisioned VigiDock GCP resources.
Cloud SQL connection: $(gcloud sql instances describe "$SQL_INSTANCE" --format='value(connectionName)')
Artifact Registry: $REGION-docker.pkg.dev/$PROJECT_ID/$ARTIFACT_REPO
GCS bucket: gs://$BUCKET
Runtime service account: $SA
OUT
