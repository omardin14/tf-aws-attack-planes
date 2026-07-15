#!/usr/bin/env bash
#
# simulate-attack.sh - fire the account-takeover attack Lambda on demand.
#
# Runs the same leaked-key attack chain that `terraform apply` fires with
# auto_fire=true, but as many times as you like, so you can re-generate the
# trigger -> detect -> investigate signal without re-applying. Each run signs its
# calls with the leaked key, trips the CloudTrail metric-filter alarms, and (when
# enable_guardduty=true) emits a GuardDuty sample finding.
#
# By default it discovers the function name and region from `terraform output`,
# so from a checkout with live state you can just run:
#
#   ./scripts/simulate-attack.sh
#
# Usage:
#   ./scripts/simulate-attack.sh [options]
#
# Options:
#   -f, --function-name NAME   Attack Lambda to invoke (default: terraform output attack_function_name)
#   -p, --name-prefix PREFIX   Derive the name as <PREFIX>-attack (matches var.name_prefix)
#   -r, --region REGION        AWS region (default: terraform output region, else $AWS_REGION)
#   -n, --count N              Fire N times (default: 1)
#   -i, --interval SECONDS     Wait SECONDS between runs (default: 0)
#   -h, --help                 Show this help
#
# Requires: aws CLI (authenticated). terraform is only needed when you don't pass
# --function-name/--region explicitly.

set -euo pipefail

# --- locate the terraform root (this script lives in <root>/scripts/) ----------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
TF_DIR="$(dirname -- "$SCRIPT_DIR")"

FUNCTION_NAME=""
NAME_PREFIX=""
REGION=""
COUNT=1
INTERVAL=0

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  # Print the leading comment block (minus the shebang) as help text.
  sed -n '3,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
  exit "${1:-0}"
}

# --- parse args ----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f | --function-name)
      FUNCTION_NAME="${2:-}"
      shift 2
      ;;
    -p | --name-prefix)
      NAME_PREFIX="${2:-}"
      shift 2
      ;;
    -r | --region)
      REGION="${2:-}"
      shift 2
      ;;
    -n | --count)
      COUNT="${2:-}"
      shift 2
      ;;
    -i | --interval)
      INTERVAL="${2:-}"
      shift 2
      ;;
    -h | --help) usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$COUNT" =~ ^[0-9]+$ && "$COUNT" -ge 1 ]] || die "--count must be a positive integer"
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval must be a non-negative integer"

command -v aws >/dev/null || die "the aws CLI is required but was not found on PATH"

# --- resolve function name + region (fall back to terraform outputs) -----------
tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || true
}

# An explicit --name-prefix wins over discovery (the function is always <prefix>-attack).
[[ -z "$FUNCTION_NAME" && -n "$NAME_PREFIX" ]] && FUNCTION_NAME="${NAME_PREFIX}-attack"

# Fall back to terraform outputs when we still need something and terraform is around.
if [[ -z "$FUNCTION_NAME" || -z "$REGION" ]] && ! command -v terraform >/dev/null; then
  die "terraform not found; pass --function-name (or --name-prefix) and --region explicitly"
fi

if [[ -z "$FUNCTION_NAME" ]]; then
  FUNCTION_NAME="$(tf_output attack_function_name)"
  # Pre-existing state (applied before the attack_function_name output was added)
  # still exposes leaked_user_name; derive the attack name from it.
  if [[ -z "$FUNCTION_NAME" ]]; then
    leaked="$(tf_output leaked_user_name)"
    [[ -n "$leaked" ]] && FUNCTION_NAME="${leaked/-leaked-ci-user/-attack}"
  fi
fi

[[ -n "$REGION" ]] || REGION="$(tf_output region)"
[[ -n "$REGION" ]] || REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

[[ -n "$FUNCTION_NAME" ]] ||
  die "could not determine the attack Lambda name. Pass --function-name or --name-prefix, or run from a checkout with live terraform state."
[[ -n "$REGION" ]] ||
  die "could not determine the region. Pass --region, or set AWS_REGION."

# --- fire ----------------------------------------------------------------------
echo ">> attack Lambda : $FUNCTION_NAME"
echo ">> region        : $REGION"
echo ">> runs          : $COUNT (interval ${INTERVAL}s)"
echo

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

for ((run = 1; run <= COUNT; run++)); do
  echo "== run $run/$COUNT =="

  # --cli-binary-format keeps the raw JSON payload readable on AWS CLI v2.
  status="$(aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION" \
    --cli-binary-format raw-in-base64-out \
    --payload "{\"trigger\":\"simulate-attack.sh\",\"run\":$run}" \
    --query 'FunctionError' --output text \
    "$RESPONSE_FILE")"

  echo "-- lambda response --"
  if command -v jq >/dev/null; then
    jq . "$RESPONSE_FILE" 2>/dev/null || cat "$RESPONSE_FILE"
  else
    cat "$RESPONSE_FILE"
  fi
  echo

  if [[ "$status" != "None" && -n "$status" ]]; then
    die "the attack Lambda reported a FunctionError ($status) on run $run - see the payload above"
  fi
  echo "[+] run $run complete"

  if [[ "$run" -lt "$COUNT" && "$INTERVAL" -gt 0 ]]; then
    echo "... sleeping ${INTERVAL}s"
    sleep "$INTERVAL"
  fi
  echo
done

echo "Done. Give CloudTrail ~1-2 min to deliver to CloudWatch Logs, then investigate:"
ATHENA_URL="$(tf_output athena_console_url)"
if [[ -n "$ATHENA_URL" ]]; then
  echo "  Athena: $ATHENA_URL"
else
  echo "  Athena: terraform -chdir=\"$TF_DIR\" output -raw athena_console_url"
fi
