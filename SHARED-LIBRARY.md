# Z-BOM Jenkins Shared Library

Jenkins plugin 설치 없이 이 GitHub 저장소를 Shared Library로 등록해서 `zbomScan(...)`을 사용할 수 있습니다.

## Jenkins 설정

Manage Jenkins -> System -> Global Pipeline Libraries:

- Name: `zbom-lib`
- Default version: `main`
- Retrieval method: Modern SCM / Git
- Project repository: 이 저장소 URL

에이전트에는 `git`, `curl`, `jq`가 있어야 합니다.

## Credentials

Jenkins Secret text credential:

- `Z_BOM_URL`: Jenkins 에이전트에서 접근 가능한 Z-BOM API URL
- `Z_BOM_TOKEN`: Z-BOM CI token
- `Z_BOM_WEB_URL`: 보고서 링크용 URL

Docker 안의 Jenkins에서 호스트 PC Z-BOM에 붙으면 `Z_BOM_URL`은 보통 `http://host.docker.internal:8000`입니다.

## Jenkinsfile

```groovy
@Library('zbom-lib') _

pipeline {
    agent any

    stages {
        stage('Z-BOM Scan') {
            steps {
                zbomScan(
                    serverUrl: 'Z_BOM_URL',
                    credentialsId: 'Z_BOM_TOKEN',
                    type: 'code',
                    failOn: 'none',
                    webUrl: 'Z_BOM_WEB_URL'
                )
            }
        }
    }
}
```

`timeoutSeconds` 기본값은 `1800`, `intervalSeconds` 기본값은 `10`입니다.

`failOn`: `none`, `critical`, `high`, `medium`, `low`
