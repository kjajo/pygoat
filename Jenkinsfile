pipeline {
  agent any

  environment {
    // Internal docker-compose network service names
    DTRACK_API = "http://dtrack-apiserver:8080/api/v1"
    DOJO_API   = "http://dojo:8081/api/v2"

    // Project identity in DTrack/Dojo
    PROJECT_NAME    = "pygoat"
    PROJECT_VERSION = "local"   // keep "local" if that's what you created in DTrack; or change to "main"

    // Bandit exclusions
    EXCLUDES = ".venv,venv,.git,build,dist,node_modules,__pycache__,site-packages"
  }

  stages {

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('SAST - Bandit') {
      steps {
        sh '''
          docker run --rm \
            -v "$PWD:/src" \
            -w /src \
            python:3.11-slim \
            bash -lc "
              mkdir -p reports &&
              pip install -q bandit==1.7.9 &&
              bandit -r . \
                -x ./.venv,./venv,./.git,./build,./dist,./node_modules,./__pycache__ \
                -f json -o reports/bandit.json
            "
        '''
      }
    }

    stage('Secrets - Gitleaks') {
      steps {
        sh '''
          mkdir -p reports
          docker run --rm \
            -v "$PWD:/repo" \
            -w /repo \
            zricethezav/gitleaks:latest detect \
              --source . --no-git \
              --report-format json --report-path reports/gitleaks.json

          # Basic count (will be 0 for "no leaks found")
          LEAKS=$(jq length reports/gitleaks.json || echo 0)
          echo "Gitleaks findings: ${LEAKS}"
        '''
      }
    }

    stage('SCA - Dependency-Track (SBOM + Upload)') {
      steps {
        withCredentials([string(credentialsId: 'DTRACK_API_KEY', variable: 'DTRACK_KEY')]) {
          sh '''
            set -eu

            mkdir -p reports

            # 1) Generate CycloneDX SBOM from requirements.txt (fallback to environment)
            docker run --rm -v "$PWD:/src" -w /src python:3.11-slim bash -lc "
              pip install -q cyclonedx-bom &&
              if [ -f requirements.txt ]; then
                cyclonedx-py requirements -i requirements.txt -o reports/bom.xml
              else
                cyclonedx-py environment -o reports/bom.xml
              fi
            "

            # 2) Lookup project UUID (robust to non-JSON responses)
            LOOKUP_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" \
              "$DTRACK_API/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION" || true)

            PROJECT_UUID=$(echo "$LOOKUP_RESP" | jq -r '.uuid // empty' 2>/dev/null || true)

            # 3) Create project if missing
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

            # 4) Upload BOM (robust)
            BOM_RESP=$(curl -sS -X POST "$DTRACK_API/bom" \
              -H "X-Api-Key: $DTRACK_KEY" \
              -F "project=$PROJECT_UUID" \
              -F "bom=@reports/bom.xml" || true)

            TOKEN=$(echo "$BOM_RESP" | jq -r '.token // empty' 2>/dev/null || true)
            echo "BOM upload token: $TOKEN"

            # 5) Optional: wait for processing if token returned
            if [ -n "$TOKEN" ]; then
              for i in $(seq 1 30); do
                TOKEN_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" "$DTRACK_API/bom/token/$TOKEN" || true)
                PROCESSING=$(echo "$TOKEN_RESP" | jq -r '.processing // false' 2>/dev/null || echo false)
                echo "Processing: $PROCESSING (try $i/30)"
                [ "$PROCESSING" = "false" ] && break
                sleep 2
              done
            else
              echo "No token returned (non-JSON or error). Skipping wait."
            fi

            # 6) Security gate: metrics (robust defaults)
            METRICS_RESP=$(curl -sS -H "X-Api-Key: $DTRACK_KEY" \
              "$DTRACK_API/metrics/project/$PROJECT_UUID/current" || true)

            CRIT=$(echo "$METRICS_RESP" | jq -r '.critical // 0' 2>/dev/null || echo 0)
            HIGH=$(echo "$METRICS_RESP" | jq -r '.high // 0' 2>/dev/null || echo 0)

            echo "Dependency-Track metrics -> critical=$CRIT high=$HIGH"

            # Gate: fail if any High/Critical
            if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
              echo "Security gate FAILED (critical=$CRIT, high=$HIGH)"
              exit 1
            fi

            echo "Security gate PASSED"
          '''
        }
      }
    }

    stage('Import to DefectDojo') {
      steps {
        withCredentials([string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DOJO_KEY')]) {
          sh '''
            set -eu
            mkdir -p reports

            ENGAGEMENT_ID=${ENGAGEMENT_ID:-1}

            # Bandit
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=Bandit Scan" \
              -F "file=@reports/bandit.json" \
              -F "active=true" -F "verified=false" || true

            # Gitleaks
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=Gitleaks Scan" \
              -F "file=@reports/gitleaks.json" \
              -F "active=true" -F "verified=false" || true

            # CycloneDX
            curl -sS -X POST "$DOJO_API/import-scan/" \
              -H "Authorization: Token $DOJO_KEY" \
              -F "engagement=$ENGAGEMENT_ID" \
              -F "scan_type=CycloneDX Scan" \
              -F "file=@reports/bom.xml" \
              -F "active=true" -F "verified=false" || true
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
