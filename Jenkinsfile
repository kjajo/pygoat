pipeline {
  agent any

  environment {
    DTRACK_API = "http://dtrack-apiserver:8080/api/v1"
    DOJO_API   = "http://dojo:8081/api/v2"

    PROJECT_NAME    = "pygoat"
    PROJECT_VERSION = "local"

    EXCLUDES = ".venv,venv,.git,build,dist,node_modules,__pycache__,site-packages"
    WORKDIR = "/var/jenkins_home/workspace/${JOB_NAME}"
  }

  stages {

    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Prepare reports dir') {
      steps {
        sh '''
          rm -rf reports
          mkdir -p reports
        '''
      }
    }

    stage('SAST - Bandit') {
      steps {
        sh '''
          mkdir -p reports

          docker run --rm \
            --volumes-from jenkins \
            -w "$WORKDIR" \
            python:3.11-slim \
            bash -lc "
              pip install -q bandit==1.7.9 &&
              mkdir -p reports &&
              bandit -r . -x $EXCLUDES -f json -o reports/bandit.json || true
            "

          ls -lah reports
          test -s reports/bandit.json
        '''
      }
    }



    stage('Secrets - Gitleaks') {
      steps {
        sh '''
          mkdir -p reports

          docker run --rm \
            --volumes-from jenkins \
            -w "$WORKDIR" \
            zricethezav/gitleaks:latest detect \
              --source . --no-git \
              --report-format json --report-path reports/gitleaks.json || true

          [ -f reports/gitleaks.json ] || echo "[]" > reports/gitleaks.json
          ls -lah reports
        '''
      }
    }


    stage('SCA - SBOM (CycloneDX)') {
      steps {
        sh '''
          mkdir -p reports

          docker run --rm \
            --volumes-from jenkins \
            -w "$WORKDIR" \
            python:3.11-slim \
            bash -lc "
              sudo apt update
              sudo apt install -y libpq-dev gcc python3-dev build-essential pkg-config libffi-dev libjpeg-dev zlib1g-dev
              set -e
              pip install -q cyclonedx-bom
              pip install -q -r requirements.txt
              mkdir -p reports
              cyclonedx-py environment -o reports/bom.xml
            "

          ls -lah reports
          test -s reports/bom.xml
        '''
      }
    }


    stage('SCA - Dependency-Track (Upload + Metrics)') {
      steps {
        withCredentials([string(credentialsId: 'DTRACK_API_KEY', variable: 'DTRACK_KEY')]) {
          sh '''
            set -eu

            # 1) Lookup project (robust)
            LOOKUP_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" \
              "$DTRACK_API/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION" || true)

            PROJECT_UUID=$(echo "$LOOKUP_RESP" | jq -r '.uuid // empty' 2>/dev/null || true)

            # 2) Create project if missing
            if [ -z "$PROJECT_UUID" ]; then
              CREATE_RESP=$(curl -sS -X PUT "$DTRACK_API/project" \
                -H "X-Api-Key: $DTRACK_KEY" \
                -H "Content-Type: application/json" \
                -d "{\"name\":\"$PROJECT_NAME\",\"version\":\"$PROJECT_VERSION\"}" || true)

              PROJECT_UUID=$(echo "$CREATE_RESP" | jq -r '.uuid // empty' 2>/dev/null || true)
            fi

            if [ -z "$PROJECT_UUID" ]; then
              echo "ERROR: Could not obtain Dependency-Track project UUID."
              echo "Lookup response: $LOOKUP_RESP"
              exit 1
            fi

            echo "Dependency-Track project UUID: $PROJECT_UUID"
            echo "$PROJECT_UUID" > reports/dtrack_project_uuid.txt

            # 3) Upload BOM (robust)
            BOM_RESP=$(curl -sS -X POST "$DTRACK_API/bom" \
              -H "X-Api-Key: $DTRACK_KEY" \
              -F "project=$PROJECT_UUID" \
              -F "bom=@reports/bom.xml" || true)

            echo "$BOM_RESP" > reports/dtrack_bom_upload_response.txt

            TOKEN=$(echo "$BOM_RESP" | jq -r '.token // empty' 2>/dev/null || true)
            echo "BOM upload token: $TOKEN"
            echo "$TOKEN" > reports/dtrack_bom_token.txt

            # 4) Wait processing (only if token exists)
            if [ -n "$TOKEN" ]; then
              for i in $(seq 1 60); do
                TOKEN_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" \
                  "$DTRACK_API/bom/token/$TOKEN" || true)

                echo "$TOKEN_RESP" > "reports/dtrack_bom_token_status_last.json" || true

                PROCESSING=$(echo "$TOKEN_RESP" | jq -r '.processing // false' 2>/dev/null || echo false)
                echo "Processing: $PROCESSING (try $i/60)"
                [ "$PROCESSING" = "false" ] && break
                sleep 2
              done
            else
              echo "WARN: No token returned by BOM upload. See reports/dtrack_bom_upload_response.txt"
            fi

            # 5) Metrics (robust defaults)
            METRICS_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" \
              "$DTRACK_API/metrics/project/$PROJECT_UUID/current" || true)

            echo "$METRICS_RESP" > reports/dtrack_metrics_current.json || true

            CRIT=$(echo "$METRICS_RESP" | jq -r '.critical // 0' 2>/dev/null || echo 0)
            HIGH=$(echo "$METRICS_RESP" | jq -r '.high // 0' 2>/dev/null || echo 0)

            echo "Dependency-Track metrics -> critical=$CRIT high=$HIGH"
            echo "{\"critical\": $CRIT, \"high\": $HIGH}" > reports/dtrack_metrics_summary.json

            # Gate (si querés que falle con HIGH/CRIT, dejalo así)
            if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
              echo "SECURITY GATE FAILED (Dependency-Track): HIGH/CRITICAL detected."
              exit 1
            fi
          '''
        }
      }
    }

    stage('Import to DefectDojo') {
      steps {
        withCredentials([string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DOJO_KEY')]) {
          sh '''
            set -eu
            ENGAGEMENT_ID=${ENGAGEMENT_ID:-1}

            # Bandit
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=Bandit Scan" \
              -F "file=@reports/bandit.json" \
              -F "active=true" -F "verified=false" \
              -o reports/dojo_import_bandit_response.txt || true

            # Gitleaks
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=Gitleaks Scan" \
              -F "file=@reports/gitleaks.json" \
              -F "active=true" -F "verified=false" \
              -o reports/dojo_import_gitleaks_response.txt || true

            # CycloneDX
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=CycloneDX Scan" \
              -F "file=@reports/bom.xml" \
              -F "active=true" -F "verified=false" \
              -o reports/dojo_import_cyclonedx_response.txt || true

          '''
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/**/*', fingerprint: true, allowEmptyArchive: true
    }
  }
}
