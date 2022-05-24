require 'dockerspec/serverspec'

describe docker_build(id: ENV['IMAGE_NAME']) do
    its(:labels) { should include 'nbs_name' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_build_id' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_build_job_repo' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_build_url' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_build_date' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_git_commit_hash' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_technical_owner' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_email' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_maintainer' => a_string_matching(/\S+/) }
    its(:labels) { should include 'nbs_product' => a_string_matching(/\S+/) }
end
