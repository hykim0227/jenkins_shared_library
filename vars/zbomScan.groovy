def call(Map args = [:]) {
    String serverUrl = (args.serverUrl ?: 'Z_BOM_URL').toString()
    String tokenId = (args.credentialsId ?: 'Z_BOM_TOKEN').toString()
    String webUrl = (args.webUrl ?: '').toString()

    List bindings = [string(credentialsId: tokenId, variable: 'ZBOM_TOKEN')]
    List envVars = [
        "ZBOM_TYPE=${args.type ?: 'code'}",
        "ZBOM_FAIL_ON=${args.failOn ?: 'none'}",
        "ZBOM_TIMEOUT=${args.timeoutSeconds ?: 1800}",
        "ZBOM_POLL=${args.intervalSeconds ?: 10}"
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
            sh(label: 'Z-BOM scan', script: '''
                set -eu

                for cmd in curl jq git; do
                  command -v "$cmd" >/dev/null || { echo "z-bom: missing command: $cmd" >&2; exit 1; }
                done

                U="${ZBOM_URL%/}"
                W="${ZBOM_WEB_URL:-$U}"
                ZIP="$(mktemp -t z-bom-source.XXXXXX)"
                trap 'rm -f "$ZIP"' EXIT

                echo "z-bom: archiving git-tracked source"
                git archive --format=zip -o "$ZIP" HEAD

                REPO="${JOB_NAME:-unknown}"
                COMMIT="${GIT_COMMIT:-$(git rev-parse HEAD)}"
                BRANCH="${BRANCH_NAME:-${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}}"
                IDEM="${REPO}:${ZBOM_TYPE}:${COMMIT}"

                echo "z-bom: submitting -> ${U}/api/ci/scan (repo=${REPO} type=${ZBOM_TYPE} commit=$(printf '%s' "$COMMIT" | cut -c1-8))"
                SUBMIT=$(curl -fsS -X POST "${U}/api/ci/scan" \
                  -H "Authorization: Token ${ZBOM_TOKEN}" \
                  -H "Idempotency-Key: ${IDEM}" \
                  -F source=JENKINS \
                  -F "repo=${REPO}" \
                  -F "type=${ZBOM_TYPE}" \
                  -F "commit=${COMMIT}" \
                  -F "branch=${BRANCH}" \
                  -F "trigger=JENKINS" \
                  -F "file=@${ZIP}")

                if [ "$(printf '%s' "$SUBMIT" | jq -r '.skipped // false')" = "true" ]; then
                  echo "z-bom: integration paused (skipped) - nothing to do"
                  exit 0
                fi

                RID=$(printf '%s' "$SUBMIT" | jq -r '.analysisRunId // empty')
                [ -n "$RID" ] || { echo "z-bom: no analysisRunId -> $SUBMIT" >&2; exit 1; }
                echo "z-bom: analysis run ${RID} (idempotent=$(printf '%s' "$SUBMIT" | jq -r '.idempotent // false'))"

                DEADLINE=$(( $(date +%s) + ZBOM_TIMEOUT ))
                STATUS="UNKNOWN"
                while :; do
                  RUN=$(curl -fsS "${U}/api/analysis-runs/${RID}" -H "Authorization: Token ${ZBOM_TOKEN}") || { echo "z-bom: poll failed" >&2; break; }
                  STATUS=$(printf '%s' "$RUN" | jq -r '.status // "UNKNOWN"')
                  echo "z-bom: status=${STATUS}"
                  case "$STATUS" in COMPLETED|FAILED) break ;; esac
                  [ "$(date +%s)" -lt "$DEADLINE" ] || { echo "z-bom: timeout after ${ZBOM_TIMEOUT}s (status=${STATUS})" >&2; break; }
                  sleep "$ZBOM_POLL"
                done

                RESULT=$(curl -fsS "${U}/api/analysis-runs/${RID}/result" -H "Authorization: Token ${ZBOM_TOKEN}" || echo '{}')
                CRIT=$(printf '%s' "$RESULT" | jq -r '.cveSeverity.CRITICAL // 0')
                HIGH=$(printf '%s' "$RESULT" | jq -r '.cveSeverity.HIGH // 0')
                MED=$(printf '%s' "$RESULT"  | jq -r '.cveSeverity.MEDIUM // 0')
                LOW=$(printf '%s' "$RESULT"  | jq -r '.cveSeverity.LOW // 0')
                TOTAL=$(printf '%s' "$RESULT" | jq -r '.totalCve // 0')
                SBOM=$(printf '%s' "$RESULT" | jq -r '.sbomCount // 0')
                HBOM=$(printf '%s' "$RESULT" | jq -r '.hbomCount // 0')
                PID=$(printf '%s' "$RESULT" | jq -r '.projectId // empty')

                printf '%s\\n' '<!-- z-bom-action -->'
                printf '## Z-BOM SBOM scan result - `%s`\\n\\n' "$STATUS"
                printf '| item | value |\\n|---|---|\\n'
                printf '| type | %s |\\n' "$ZBOM_TYPE"
                printf '| components | SBOM %s / HBOM %s |\\n' "$SBOM" "$HBOM"
                printf '| vulnerabilities | Critical %s / High %s / Medium %s / Low %s (total %s) |\\n\\n' "$CRIT" "$HIGH" "$MED" "$LOW" "$TOTAL"
                [ -n "$PID" ] && printf 'Report: %s/project/%s/summary\\n\\n' "${W%/}" "$PID"

                [ "$STATUS" = "FAILED" ] && { echo "z-bom: analysis failed" >&2; exit 1; }
                case "$ZBOM_FAIL_ON" in
                  critical) GATE=$CRIT ;;
                  high) GATE=$((CRIT + HIGH)) ;;
                  medium) GATE=$((CRIT + HIGH + MED)) ;;
                  low) GATE=$((CRIT + HIGH + MED + LOW)) ;;
                  none) GATE=0 ;;
                  *) echo "z-bom: invalid failOn=${ZBOM_FAIL_ON}" >&2; exit 1 ;;
                esac
                if [ "$ZBOM_FAIL_ON" != "none" ] && [ "$GATE" -gt 0 ]; then
                  echo "z-bom: fail-on=${ZBOM_FAIL_ON} matched ${GATE} CVE(s)" >&2
                  exit 1
                fi
                echo "z-bom: done"
            ''')
        }
    }
}
