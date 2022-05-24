@Library('jenkins-infra-build-libs') _
import org.nw.build.models.DockerTarget

def atlas_exp = new DockerTarget(name: 'atlas-logs-exporter',
       path: ".",
       repo: "odp/mongo-logs-exporter",
       testspec: "tests/spec")

dockerImagePipeline "targets": [atlas_exp]
