pipeline {
  agent any

  environment {
    // URLs internas desde el contenedor Jenkins (misma red docker compose)
    DTRACK_API = "http://dtrack-apiserver:8080/api/v1"
    DOJO_API   = "http://dojo:8080/api/v2"

    // Nombre/version del proyecto en DTrack (ajusta a gusto)
    PROJECT_NAME = "pygoat"
    PROJECT_VERSION = "local"
  }

  options {
    timestamps()
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
          mkdir -p reports
          # Bandit via contenedor (evita instalar dependencias locales)
          docker run --rm -v "$PWD:/src" -w /src python:3.11-slim bash -lc "
            pip install -q bandit==1.7.9 &&
            bandit -r . \
              -x ./.venv,./venv,./.git,./build,./dist,./node_modules,./__pycache__ \
              -f json -o reports/bandit.json
          "

          # Gate: falla si existe al menos 1 issue con severity HIGH
          HIGH_COUNT=$(jq '[.results[] | select(.issue_severity=="HIGH")] | length' reports/bandit.json)
          echo "Bandit HIGH findings: $HIGH_COUNT"
          if [ "$HIGH_COUNT" -gt 0 ]; then
            echo "Security gate failed: Bandit has HIGH findings."
            exit 1
          fi
        '''
      }
    }

    stage('Secrets - Gitleaks') {
      steps {
        sh '''
          mkdir -p reports
          docker run --rm -v "$PWD:/repo" -w /repo zricethezav/gitleaks:latest \
            detect --source . --no-git --report-format json --report-path reports/gitleaks.json || true

          # Gate opcional (si querés): falla si hay leaks
          LEAKS=$(jq 'length' reports/gitleaks.json 2>/dev/null || echo 0)
          echo "Gitleaks findings: $LEAKS"
        '''
      }
    }

    stage('SCA - Dependency-Track (SBOM + Upload)') {
      steps {
        withCredentials([string(credentialsId: 'DTRACK_API_KEY', variable: 'DTRACK_KEY')]) {
          sh '''
            mkdir -p reports

            # 1) Generar SBOM CycloneDX (ajustá el input si tu proyecto no tiene requirements.txt)
            docker run --rm -v "$PWD:/src" -w /src python:3.11-slim bash -lc "
              pip install -q cyclonedx-bom &&
              if [ -f requirements.txt ]; then
                cyclonedx-py requirements -i requirements.txt -o reports/bom.xml
              else
                # fallback: intenta detectar entorno python
                cyclonedx-py environment -o reports/bom.xml
              fi
            "

            # 2) Crear/obtener proyecto en Dependency-Track
            PROJECT_UUID=$(curl -sS -X GET "$DTRACK_API/project/lookup?name=$PROJECT_NAME&version=$PROJECT_VERSION" \
              -H "X-Api-Key: $DTRACK_KEY" | jq -r '.uuid // empty')

            if [ -z "$PROJECT_UUID" ]; then
              PROJECT_UUID=$(curl -sS -X PUT "$DTRACK_API/project" \
                -H "X-Api-Key: $DTRACK_KEY" -H "Content-Type: application/json" \
                -d "{\"name\":\"$PROJECT_NAME\",\"version\":\"$PROJECT_VERSION\"}" | jq -r '.uuid')
            fi

            echo "Dependency-Track project uuid: $PROJECT_UUID"

            # 3) Subir SBOM
            TOKEN=$(curl -sS -X POST "$DTRACK_API/bom" \
              -H "X-Api-Key: $DTRACK_KEY" \
              -F "project=$PROJECT_UUID" \
              -F "bom=@reports/bom.xml" | jq -r '.token')

            echo "BOM upload token: $TOKEN"

            # 4) Esperar a que procese (poll simple)
            for i in $(seq 1 30); do
              PROCESSING=$(curl -sS -X GET "$DTRACK_API/bom/token/$TOKEN" -H "X-Api-Key: $DTRACK_KEY" | jq -r '.processing')
              echo "Processing: $PROCESSING (try $i/30)"
              if [ "$PROCESSING" = "false" ]; then break; fi
              sleep 2
            done

            # 5) Gate: falla si hay HIGH o CRITICAL
            METRICS=$(curl -sS -X GET "$DTRACK_API/metrics/project/$PROJECT_UUID/current" -H "X-Api-Key: $DTRACK_KEY")
            CRIT=$(echo "$METRICS" | jq -r '.critical // 0')
            HIGH=$(echo "$METRICS" | jq -r '.high // 0')
            echo "Dependency-Track metrics -> critical=$CRIT high=$HIGH"

            if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
              echo "Security gate failed: Dependency-Track has HIGH/CRITICAL vulnerabilities."
              exit 1
            fi

            # Guardamos uuid para siguientes stages
            echo "$PROJECT_UUID" > reports/dtrack_project_uuid.txt
          '''
        }
      }
    }

    stage('Push results to DefectDojo') {
      steps {
        withCredentials([
          string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DOJO_KEY')
        ]) {
          sh '''
            # NOTA: necesitás tener creado en DefectDojo:
            # - Product
            # - Engagement (o lo creás por API)
            # Para ir rápido: crealo manual una vez (Product: pygoat, Engagement: pipeline)
            #
            # Luego ponés acá el ENGAGEMENT_ID.
            #
            # Tip: si querés automatizar la creación por API, lo hacemos en el siguiente paso.
            ENGAGEMENT_ID=1

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

            # Dependency-Track (opciones)
            # Algunas instalaciones soportan import directo desde SBOM o "Dependency Track Findings Import".
            # Empezamos subiendo el SBOM como evidencia:
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
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
    }
  }
}

