import groovy.json.JsonSlurperClassic

def call(Map args = [:]) {
    String serverUrl = (args.serverUrl ?: 'Z_BOM_URL').toString()
    String tokenId = (args.credentialsId ?: 'Z_BOM_TOKEN').toString()
    String webUrl = (args.webUrl ?: '').toString()
    String failOn = (args.failOn ?: 'none').toString()
    int timeoutSeconds = (args.timeoutSeconds ?: 1800) as int
    int pollSeconds = (args.intervalSeconds ?: 10) as int

    List bindings = [string(credentialsId: tokenId, variable: 'ZBOM_TOKEN')]
    List envVars = [
        "ZBOM_TYPE=${args.type ?: 'code'}",
        "ZBOM_FAIL_ON=${failOn}",
        "ZBOM_TIMEOUT=${timeoutSeconds}",
        "ZBOM_POLL=${pollSeconds}"
    ]

    if (serverUrl ==~ /^https?:\/\/.+/) {
        envVars << "ZBOM_URL=${serverUrl}"
    } else {
        bindings << string(credentialsId: serverUrl, variable: 'ZBOM_URL')
    }

    if (webUrl) {
        if (webUrl ==~ /^https?:\/\/.+/) {
            envVars << "ZBOM_WEB_URL=${webUrl}"
        } else {
            bindings << string(credentialsId: webUrl, variable: 'ZBOM_WEB_URL')
        }
    }

    withCredentials(bindings) {
        withEnv(envVars) {
            String submitText = sh(label: 'Z-BOM submit', returnStdout: true, script: '''
                set -eu

                for cmd in curl git; do
                  command -v "$cmd" >/dev/null || { echo "z-bom: missing command: $cmd" >&2; exit 1; }
                done

                U="${ZBOM_URL%/}"
                ZIP="$(mktemp -t z-bom-source.XXXXXX)"
                trap 'rm -f "$ZIP"' EXIT

                echo "z-bom: archiving git-tracked source" >&2
                git archive --format=zip -o "$ZIP" HEAD

                REPO="${JOB_NAME:-unknown}"
                COMMIT="${GIT_COMMIT:-$(git rev-parse HEAD)}"
                BRANCH="${BRANCH_NAME:-${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}}"
                IDEM="${REPO}:${ZBOM_TYPE}:${COMMIT}"

                echo "z-bom: submitting -> ${U}/api/ci/scan (repo=${REPO} type=${ZBOM_TYPE} commit=$(printf '%s' "$COMMIT" | cut -c1-8))" >&2
                curl -fsS -X POST "${U}/api/ci/scan" \
                  -H "Authorization: Token ${ZBOM_TOKEN}" \
                  -H "Idempotency-Key: ${IDEM}" \
                  -F source=JENKINS \
                  -F "repo=${REPO}" \
                  -F "type=${ZBOM_TYPE}" \
                  -F "commit=${COMMIT}" \
                  -F "branch=${BRANCH}" \
                  -F "trigger=JENKINS" \
                  -F "file=@${ZIP};filename=source.zip"
            ''').trim()

            Map submit = json(submitText)
            if (submit.skipped == true) {
                echo 'z-bom: integration paused (skipped) - nothing to do'
                return
            }

            String runId = (submit.analysisRunId ?: '').toString()
            if (!runId) {
                error "z-bom: no analysisRunId -> ${submitText}"
            }
            echo "z-bom: analysis run ${runId} (idempotent=${submit.idempotent ?: false})"

            long deadline = System.currentTimeMillis() + (timeoutSeconds * 1000L)
            String status = 'UNKNOWN'
            while (true) {
                Map run = json(sh(label: 'Z-BOM poll', returnStdout: true, script: """
                    set -eu
                    curl -fsS "\${ZBOM_URL%/}/api/analysis-runs/${runId}" -H "Authorization: Token \${ZBOM_TOKEN}"
                """).trim())
                status = (run.status ?: 'UNKNOWN').toString()
                echo "z-bom: status=${status}"
                if (status in ['COMPLETED', 'FAILED']) {
                    break
                }
                if (System.currentTimeMillis() >= deadline) {
                    echo "z-bom: timeout after ${timeoutSeconds}s (status=${status})"
                    break
                }
                sleep time: pollSeconds, unit: 'SECONDS'
            }

            Map result = json(sh(label: 'Z-BOM result', returnStdout: true, script: """
                set -eu
                curl -fsS "\${ZBOM_URL%/}/api/analysis-runs/${runId}/result" -H "Authorization: Token \${ZBOM_TOKEN}" || echo '{}'
            """).trim())
            Map severity = (result.cveSeverity ?: [:]) as Map
            int critical = intValue(severity.CRITICAL)
            int high = intValue(severity.HIGH)
            int medium = intValue(severity.MEDIUM)
            int low = intValue(severity.LOW)
            int total = intValue(result.totalCve)
            int sbom = intValue(result.sbomCount)
            int hbom = intValue(result.hbomCount)
            String projectId = (result.projectId ?: '').toString()
            String reportBase = sh(returnStdout: true, script: 'printf %s "${ZBOM_WEB_URL:-$ZBOM_URL}"').trim()

            echo """<!-- z-bom-action -->
## Z-BOM SBOM scan result - `${status}`

| item | value |
|---|---|
| type | ${env.ZBOM_TYPE} |
| components | SBOM ${sbom} / HBOM ${hbom} |
| vulnerabilities | Critical ${critical} / High ${high} / Medium ${medium} / Low ${low} (total ${total}) |
${projectId ? "\nReport: ${reportBase.replaceAll('/+$', '')}/project/${projectId}/summary\n" : ''}"""

            if (status == 'FAILED') {
                error 'z-bom: analysis failed'
            }

            int gate = 0
            switch (failOn) {
                case 'none':
                    gate = 0
                    break
                case 'critical':
                    gate = critical
                    break
                case 'high':
                    gate = critical + high
                    break
                case 'medium':
                    gate = critical + high + medium
                    break
                case 'low':
                    gate = critical + high + medium + low
                    break
                default:
                    error "z-bom: invalid failOn=${failOn}"
            }
            if (failOn != 'none' && gate > 0) {
                error "z-bom: fail-on=${failOn} matched ${gate} CVE(s)"
            }
            echo 'z-bom: done'
        }
    }
}

private Map json(String text) {
    new JsonSlurperClassic().parseText(text ?: '{}') as Map
}

private int intValue(Object value) {
    value == null ? 0 : value.toString().toInteger()
}
