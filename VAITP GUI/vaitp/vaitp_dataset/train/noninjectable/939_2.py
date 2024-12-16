name: Generate changeset
on:
  workflow_run:
    workflows: ["trigger changeset generation"]
    types:
      - completed

env:
  CI: true
  NODE_OPTIONS: "--max-old-space-size=4096"

concurrency:
  group: ${{ github.event.workflow_run.head_repository.full_name }}::${{ github.event.workflow_run.head_branch }}

jobs:
  get-pr:
    runs-on: ubuntu-latest
    if: github.event.workflow_run.conclusion == 'success'
    outputs:
      found_pr: ${{ steps.pr_details.outputs.found_pr }}
      pr_number: ${{ steps.pr_details.outputs.pr_number }}
      source_repo: ${{ steps.pr_details.outputs.source_repo }}
      source_branch: ${{ steps.pr_details.outputs.source_branch }}
    steps:
    - name: echo concurrency group
      run: echo ${{ github.event.workflow_run.head_repository.full_name }}::${{ github.event.workflow_run.head_branch }}
    - name: get pr details
      id: pr_details
      uses: gradio-app/github/actions/find-pr@main
      with:
        github_token: ${{ secrets.GITHUB_TOKEN }}
  comment-changes-start:
    uses: "./.github/workflows/comment-queue.yml"
    needs: get-pr
    secrets:
      gh_token: ${{ secrets.COMMENT_TOKEN }}
    with:
      pr_number: ${{ needs.get-pr.outputs.pr_number }}
      message: changes~pending~null
  version:
    permissions: write-all
    name: static checks
    needs: get-pr
    runs-on: ubuntu-22.04
    if: needs.get-pr.outputs.found_pr == 'true'
    outputs:
      skipped: ${{ steps.version.outputs.skipped }}
      comment_url: ${{ steps.version.outputs.comment_url }}
    steps:
      - uses: actions/checkout@v3
        with:
          repository: ${{ needs.get-pr.outputs.source_repo }}
          ref: ${{ needs.get-pr.outputs.source_branch }}
          fetch-depth: 0
          token: ${{ secrets.COMMENT_TOKEN }}
      - name: generate changeset
        id: version
        uses: "gradio-app/github/actions/generate-changeset@main"
        with: 
          github_token: ${{ secrets.COMMENT_TOKEN }}
          main_pkg: gradio
          pr_number: ${{ needs.get-pr.outputs.pr_number }}
          branch_name: ${{ needs.get-pr.outputs.source_branch }}
  comment-changes-skipped:
    uses: "./.github/workflows/comment-queue.yml"
    needs: [get-pr, version]
    if: needs.version.result == 'success' && needs.version.outputs.skipped == 'true'
    secrets:
      gh_token: ${{ secrets.COMMENT_TOKEN }}
    with:
      pr_number: ${{ needs.get-pr.outputs.pr_number }}
      message: changes~warning~https://github.com/gradio-app/gradio/actions/runs/${{github.run_id}}/
  comment-changes-success:
    uses: "./.github/workflows/comment-queue.yml"
    needs: [get-pr, version]
    if: needs.version.result == 'success' && needs.version.outputs.skipped == 'false'
    secrets:
      gh_token: ${{ secrets.COMMENT_TOKEN }}
    with:
      pr_number: ${{ needs.get-pr.outputs.pr_number }}
      message: changes~success~${{ needs.version.outputs.comment_url }}
  comment-changes-failure:
    uses: "./.github/workflows/comment-queue.yml"
    needs: [get-pr, version]
    if: always() && needs.version.result == 'failure'
    secrets:
      gh_token: ${{ secrets.COMMENT_TOKEN }}
    with:
      pr_number: ${{ needs.get-pr.outputs.pr_number }}
      message: changes~failure~https://github.com/gradio-app/gradio/actions/runs/${{github.run_id}}/