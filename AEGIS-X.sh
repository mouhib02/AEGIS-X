#!/usr/bin/env bash

# ==============================================================================
# AEGIS-X.sh — God-Mode Autonomous Recon & Discovery Engine
# Author: For the hunter who will earn their first bounty
# WARNING: Use only against assets you are authorized to test.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ------------------------ GLOBALS --------------------------------------------
BASE_DIR="${HOME}/aegisx"
PROJECT_DIR=""
STATE_FILE=""
LOG_FILE=""
CONFIG_FILE=""
PROJECT=""

readonly VERSION="3.0.1-final"

# Color helpers
cprint() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
info() { cprint "36" "[*] $*"; }
success() { cprint "32" "[+] $*"; }
warn() { cprint "33" "[!] $*"; }
error() { cprint "31" "[-] $*" >&2; }

# ------------------------ HELPERS --------------------------------------------
date_now() { date +"%F_%H-%M-%S"; }
timestamp() { date +"%F %T"; }

log() {
    local msg="$*"
    [[ -n "${LOG_FILE:-}" ]] && printf "[%s] %s\n" "$(timestamp)" "$msg" | tee -a "$LOG_FILE" || printf "[%s] %s\n" "$(timestamp)" "$msg"
}

err() {
    local msg="$*"
    [[ -n "${LOG_FILE:-}" ]] && printf "[%s] ERROR: %s\n" "$(timestamp)" "$msg" >&2 | tee -a "$LOG_FILE" || printf "[%s] ERROR: %s\n" "$(timestamp)" "$msg" >&2
    exit 1
}

# ------------------------ JSON STATE ----------------------------------------
json_set() {
    local file="$1" key="$2" val="$3"
    [[ -f "$file" ]] || echo '{}' > "$file"
    tmp=$(mktemp)
    jq --arg k "$key" --arg v "$val" '.[$k]=$v' "$file" > "$tmp" && mv "$tmp" "$file"
}

json_get() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || { echo ""; return 1; }
    jq -r --arg k "$key" 'if has($k) then .[$k] else "" end' "$file"
}

mark_done() { json_set "$STATE_FILE" "$1" "done"; }
step_done() { [[ "$(json_get "$STATE_FILE" "$1")" == "done" ]]; }

# ------------------------ NOTIFICATIONS --------------------------------------
notify() {
    local msg="$1"
    local disable_preview="${2:-false}"
    if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            -d text="$msg" \
            -d disable_web_page_preview="$disable_preview" \
            -d parse_mode="HTML" >/dev/null || true
    fi
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\": \"$msg\"}" "$SLACK_WEBHOOK_URL" >/dev/null || true
    fi
    if [[ -n "${GENERIC_WEBHOOK_URL:-}" ]]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"message\": \"$msg\"}" "$GENERIC_WEBHOOK_URL" >/dev/null || true
    fi
}

# ------------------------ DEP CHECK ------------------------------------------
check_deps() {
    local missing=()
    local optional=()
    local tools_required=(subfinder amass httpx nuclei jq curl grep awk sed xargs)
    local tools_optional=(gau waybackurls dalfox katana gowitness aquatone naabu nmap aws mc feroxbuster parallel)
    for t in "${tools_required[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            missing+=("$t")
        fi
    done
    for t in "${tools_optional[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            optional+=("$t")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}. Install them before running."
    fi
    if [[ ${#optional[@]} -gt 0 ]]; then
        warn "Optional tools not found: ${optional[*]}"
    fi
}

# ------------------------ RETRY HELPER ---------------------------------------
retry() {
    local max="${1:-3}"; shift
    local wait="${1:-3}"; shift
    local i=0
    until "$@" || [[ $i -ge $max ]]; do
        i=$((i+1))
        sleep "$wait"
    done
    (( i < max )) || warn "Command failed after $max attempts: $*"
    return $?
}

# ------------------------ SCAFFOLD PROJECT -----------------------------------
scaffold_project() {
    local project="$1"; local domain="$2"; local mode="$3"
    PROJECT_DIR="$BASE_DIR/$project"
    STATE_FILE="$PROJECT_DIR/logs/state.json"
    LOG_FILE="$PROJECT_DIR/logs/execution.log"
    CONFIG_FILE="$PROJECT_DIR/config.env"

    mkdir -p "$PROJECT_DIR"/{passive,active/{live,screenshots},vulns,raw,reports,logs/raw,notes}

    cat > "$CONFIG_FILE" <<EOF
# AEGIS-X Configuration
PROJECT_NAME="$project"
TARGET_DOMAIN="$domain"
SCAN_MODE="$mode"
RATE_LIMIT=5
CUSTOM_HEADER="X-Intigriti-Username: mouhibmha"
EXCLUDE_PATHS="login|logout|inloggen|registreren|service"
EXCLUDE_SUBDOMAINS="abonnement\\.ad\\.nl|dev\\.internal"
TIMEOUT=10
RETRIES=1
ENABLE_FUZZING=0
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""
GENERIC_WEBHOOK_URL=""
S3_BUCKET=""
MINIO_ALIAS=""
MINIO_BUCKET=""
MINIO_ENDPOINT=""
MINIO_KEY=""
MINIO_SECRET=""
EOF

    echo '{}' > "$STATE_FILE"
    touch "$LOG_FILE"
    log "Project '$project' initialized in $PROJECT_DIR"
    success "Run: ./AEGIS-X.sh run $project"
    notify "🟢 <b>Project Initialized</b>
• Name: $project
• Domain: $domain
• Mode: $mode" "true"
}

# ------------------------ LOAD CONFIG ----------------------------------------
load_config() {
    if [[ -z "${PROJECT_DIR:-}" ]]; then err "PROJECT_DIR not set"; fi
    CONFIG_FILE="$PROJECT_DIR/config.env"
    STATE_FILE="$PROJECT_DIR/logs/state.json"
    LOG_FILE="$PROJECT_DIR/logs/execution.log"
    [[ -f "$CONFIG_FILE" ]] || err "Config not found: $CONFIG_FILE"
    set -a
    source "$CONFIG_FILE"
    set +a
    TARGET_DOMAIN="$(echo "${TARGET_DOMAIN:-}" | sed 's/[^A-Za-z0-9._-]//g')"
    mkdir -p "$PROJECT_DIR/logs/raw"
    PROJECT="$PROJECT_NAME"
}

# ------------------------ PASSIVE RECON --------------------------------------
run_passive() {
    step_done "passive_done" && info "Passive recon already completed" && return
    info "Starting passive subdomain discovery..."
    trap 'rm -f /tmp/aegis_live.tmp' EXIT

    local out_dir="$PROJECT_DIR/passive"
    mkdir -p "$out_dir"

    retry 3 2 subfinder -d "$TARGET_DOMAIN" -silent -nW > "$out_dir/subfinder.txt" 2>>"$PROJECT_DIR/logs/raw/subfinder.err" || true
    retry 2 3 amass enum -d "$TARGET_DOMAIN" -passive -silent > "$out_dir/amass.txt" 2>>"$PROJECT_DIR/logs/raw/amass.err" || true

    if command -v gau &>/dev/null; then
        echo "$TARGET_DOMAIN" | gau --threads 5 --timeout 30 2>>"$PROJECT_DIR/logs/raw/gau.err" | grep -E "\.$TARGET_DOMAIN" > "$out_dir/gau.txt" || true
    fi

    (cat "$out_dir/subfinder.txt" "$out_dir/amass.txt" 2>/dev/null | sort -u) | httpx -silent -o /tmp/aegis_live.tmp 2>>"$PROJECT_DIR/logs/raw/httpx_probe.err" || true

    if command -v waybackurls &>/dev/null; then
        while IFS= read -r url; do
            waybackurls "$url" 2>>"$PROJECT_DIR/logs/raw/wayback.err" | grep -E "\.$TARGET_DOMAIN" >> "$out_dir/wayback.txt" || true
            sleep 0.05
        done < /tmp/aegis_live.tmp
    fi

    cat "$out_dir"/*.txt 2>/dev/null | grep -vE "$EXCLUDE_SUBDOMAINS|$EXCLUDE_PATHS" | sort -u > "$out_dir/subdomains.txt" || true
    local count=0
    [[ -s "$out_dir/subdomains.txt" ]] && count=$(wc -l < "$out_dir/subdomains.txt")
    json_set "$STATE_FILE" "subdomain_count" "$count"
    log "Passive: Found $count subdomains"

    notify "🟢 <b>Passive Recon Done</b>
• Subdomains: $count
• Domain: $TARGET_DOMAIN" "true"
    mark_done "passive_done"
}

# ------------------------ ACTIVE RECON ---------------------------------------
run_active() {
    step_done "active_done" && info "Active recon already completed" && return
    info "Probing live hosts (parallel httpx)..."

    local subs="$PROJECT_DIR/passive/subdomains.txt"
    local live="$PROJECT_DIR/active/live/hosts.txt"
    mkdir -p "$(dirname "$live")"

    if [[ ! -s "$subs" ]]; then
        warn "No subdomains found."
        mark_done "active_done"
        return
    fi

    : > "$live"
    local parallelism=10
    if command -v parallel &>/dev/null; then
        parallelism=20
        cat "$subs" | parallel -j "$parallelism" --no-notice httpx -silent -H "$CUSTOM_HEADER" -o - 2>>"$PROJECT_DIR/logs/raw/httpx.err" >> "$live" || true
    else
        cat "$subs" | xargs -P "$parallelism" -I{} sh -c "echo {} | httpx -silent -H \"$CUSTOM_HEADER\"" 2>>"$PROJECT_DIR/logs/raw/httpx.err" >> "$live" || true
    fi

    sort -u "$live" -o "$live" || true
    local count=0
    [[ -s "$live" ]] && count=$(wc -l < "$live")
    json_set "$STATE_FILE" "live_count" "$count"
    log "Active: $count live hosts"

    notify "🔵 <b>Live Hosts Found</b>
• Count: $count
• Probed with httpx + header" "true"
    mark_done "active_done"
}

# ------------------------ SCREENSHOTS ----------------------------------------
run_screenshots() {
    step_done "screenshot_done" && info "Screenshots already done" && return
    info "Capturing screenshots..."

    local live="$PROJECT_DIR/active/live/hosts.txt"
    local out_dir="$PROJECT_DIR/active/screenshots"
    mkdir -p "$out_dir"

    if [[ ! -s "$live" ]]; then
        warn "No live hosts to screenshot."
        mark_done "screenshot_done"
        return
    fi

    if command -v gowitness &>/dev/null; then
        gowitness file -f "$live" -P "$out_dir" --disable-db --timeout 15 2>>"$PROJECT_DIR/logs/raw/gowitness.err" || true
    fi
    if command -v aquatone &>/dev/null; then
        cat "$live" | aquatone -out "$out_dir/aquatone" 2>>"$PROJECT_DIR/logs/raw/aquatone.err" || true
    fi

    local count=0
    count=$(ls "$out_dir"/*.png 2>/dev/null | wc -l || echo 0)
    notify "📸 <b>Screenshots Captured</b>
• Count: $count
• Path: $out_dir/" "true"
    mark_done "screenshot_done"
}

# ------------------------ CTF MODE -------------------------------------------
run_ctf_mode() {
    info "Running CTF mode..."
    local live="$PROJECT_DIR/active/live/hosts.txt"
    local flags=()

    while IFS= read -r url; do
        content=$(curl -skL "$url" | grep -Eo 'flag\{[^}]+\}' | head -5)
        if [[ -n "$content" ]]; then
            flags+=("$url: $content")
        fi
    done < "$live"

    if [[ ${#flags[@]} -gt 0 ]]; then
        printf '%s\n' "${flags[@]}" > "$PROJECT_DIR/vulns/flags.txt"
        notify "🚩 <b>CTF Flags Found!</b>
${flags[0]:0:300}..." "true"
    fi
}

# ------------------------ VULN SCAN ------------------------------------------
generate_severity_map() {
    local out="$PROJECT_DIR/vulns/severity_map.json"
    jq -n '{}' > "$out"
    severity_rank() {
        case "$1" in critical) echo 1 ;; high) echo 2 ;; medium) echo 3 ;; low) echo 4 ;; *) echo 5 ;; esac
    }

    for file in "$PROJECT_DIR/vulns/nuclei.txt" "$PROJECT_DIR/vulns/xss.txt"; do
        [[ -f "$file" ]] || continue
        while IFS= read -r line; do
            host=$(echo "$line" | awk '{print $1}' | sed 's#https\?://##;s#/.*##' )
            sev=$(echo "$line" | grep -Eo '\[critical\]|\[high\]|\[medium\]|\[low\]' | tr -d '[]' | tr '[:upper:]' '[:lower:]' | head -n1)
            [[ -z "$host" || -z "$sev" ]] && continue
            existing=$(jq -r --arg h "$host" '.[ $h ] // ""' "$out")
            if [[ -z "$existing" || "$(severity_rank "$sev")" -lt "$(severity_rank "$existing")" ]]; then
                jq --arg h "$host" --arg s "$sev" '. + {($h): $s}' "$out" > /tmp/tmp.$$.json && mv /tmp/tmp.$$.json "$out"
            fi
        done < "$file"
    done
}

run_vuln_scan() {
    step_done "vuln_done" && info "Vulnerability scan already completed" && return
    info "Running vulnerability detection..."

    local live="$PROJECT_DIR/active/live/hosts.txt"
    local nuclei_out="$PROJECT_DIR/vulns/nuclei.txt"
    local dalfox_out="$PROJECT_DIR/vulns/xss.txt"
    mkdir -p "$PROJECT_DIR/vulns"

    if command -v nuclei &>/dev/null; then
        nuclei -update-templates -silent 2>>"$PROJECT_DIR/logs/raw/nuclei.update.err" || true
        if [[ -s "$live" ]]; then
            timeout 30m nuclei -l "$live" -t ~/nuclei-templates -severity medium,high,critical -rate-limit "$RATE_LIMIT" -timeout "$TIMEOUT" -H "$CUSTOM_HEADER" -o "$nuclei_out" -silent 2>>"$PROJECT_DIR/logs/raw/nuclei.err" || true
            local high=0
            high=$(grep -Eoi '\[critical\]|\[high\]' "$nuclei_out" 2>/dev/null | wc -l || echo 0)
            if [[ $high -gt 0 ]]; then
                notify "🚨 <b>CRITICAL Vulnerabilities Found!</b>
• High/Critical: $high
• Check: $PROJECT_DIR/vulns/nuclei.txt" "true"
            fi
        fi
    else
        warn "nuclei not installed — skipping nuclei scan."
    fi

    if command -v dalfox &>/dev/null && [[ -s "$PROJECT_DIR/passive/wayback.txt" ]]; then
        cat "$PROJECT_DIR/passive/wayback.txt" | dalfox pipe --silence -rate-limit "$RATE_LIMIT" -H "$CUSTOM_HEADER" -o "$dalfox_out" 2>>"$PROJECT_DIR/logs/raw/dalfox.err" || true
        if [[ -s "$dalfox_out" ]] && grep -iq "poc" "$dalfox_out"; then
            notify "🟢 <b>XSS Signal Detected</b>
• Potential XSS found
• Check: $PROJECT_DIR/vulns/xss.txt" "true"
        fi
    fi

    generate_severity_map
    mark_done "vuln_done"
}

# ------------------------ REPORT ---------------------------------------------
generate_report() {
    local report="$PROJECT_DIR/reports/final-$(date_now).html"
    local sub_count=$(json_get "$STATE_FILE" "subdomain_count" || echo 0)
    local live_count=$(json_get "$STATE_FILE" "live_count" || echo 0)
    local vuln_count=$( [[ -s "$PROJECT_DIR/vulns/nuclei.txt" ]] && wc -l < "$PROJECT_DIR/vulns/nuclei.txt" || echo 0 )
    local xss_count=$( [[ -s "$PROJECT_DIR/vulns/xss.txt" ]] && grep -c "POC" "$PROJECT_DIR/vulns/xss.txt" || echo 0 )

    cat > "$report" <<HTML
<!DOCTYPE html>
<html>
<head><title>AEGIS-X Report — $PROJECT_NAME</title>
<style>body{font-family:Arial;padding:20px} .card{border:1px solid #ccc;padding:15px;margin:10px 0;border-radius:8px}</style>
</head>
<body>
<h1>AEGIS-X Final Report</h1>
<p><strong>Project:</strong> $PROJECT_NAME<br>
<strong>Mode:</strong> $SCAN_MODE<br>
<strong>Date:</strong> $(date)</p>

<div class="card">
<h3>Summary</h3>
<ul>
<li>Subdomains: $sub_count</li>
<li>Live Hosts: $live_count</li>
<li>Vulnerabilities Found: $vuln_count</li>
<li>XSS POCs: $xss_count</li>
</ul>
</div>

<div class="card">
<h3>Next Steps</h3>
<ol>
<li>Manually verify findings</li>
<li>Check for business logic flaws</li>
<li>Submit with detailed reproduction steps</li>
</ol>
</div>

<p><em>This report was generated by AEGIS-X — Built for ethical hunters.</em></p>
</body>
</html>
HTML

    success "Report generated: file://$report"
    notify "🎯 <b>Scan Completed: $PROJECT_NAME</b>
• Mode: $SCAN_MODE
• Subdomains: $sub_count
• Live Hosts: $live_count
• High/Critical Vulns: $vuln_count
• XSS POCs: $xss_count
• Report: $report" "true"
}

# ------------------------ S3 / MINIO UPLOAD ----------------------------------
upload_reports() {
    if [[ -n "${S3_BUCKET:-}" && -n "$(command -v aws || true)" ]]; then
        aws s3 sync "$PROJECT_DIR/reports" "s3://$S3_BUCKET/$PROJECT_NAME/reports/" --exact-timestamps 2>>"$PROJECT_DIR/logs/raw/aws.err" || warn "aws s3 sync failed"
        aws s3 sync "$PROJECT_DIR/active/screenshots" "s3://$S3_BUCKET/$PROJECT_NAME/screenshots/" --exact-timestamps 2>>"$PROJECT_DIR/logs/raw/aws.err" || warn "aws s3 sync failed"
        notify "📤 Reports uploaded to S3: $S3_BUCKET" "true"
    fi
    if [[ -n "${MINIO_ALIAS:-}" && -n "${MINIO_BUCKET:-}" && -n "$(command -v mc || true)" ]]; then
        mc alias set "$MINIO_ALIAS" "$MINIO_ENDPOINT" "$MINIO_KEY" "$MINIO_SECRET" 2>>"$PROJECT_DIR/logs/raw/mc.err" || warn "mc alias set failed"
        mc mirror "$PROJECT_DIR/reports" "$MINIO_ALIAS/$MINIO_BUCKET/$PROJECT_NAME/reports" 2>>"$PROJECT_DIR/logs/raw/mc.err" || warn "mc mirror reports failed"
        mc mirror "$PROJECT_DIR/active/screenshots" "$MINIO_ALIAS/$MINIO_BUCKET/$PROJECT_NAME/screenshots" 2>>"$PROJECT_DIR/logs/raw/mc.err" || warn "mc mirror screenshots failed"
        notify "📤 Reports uploaded to Minio: $MINIO_BUCKET" "true"
    fi
}

# ------------------------ TEST NOTIFY ---------------------------------------
test_notify() {
    load_config
    notify "🧪 <b>AEGIS-X Test Notification</b>
Project: $PROJECT_NAME
Time: $(date)" "true"
    success "Test notification sent."
}

# ------------------------ MAIN PIPELINE --------------------------------------
run_pipeline() {
    local project="$1"
    PROJECT_DIR="$BASE_DIR/$project"
    [[ -d "$PROJECT_DIR" ]] || err "Project not found: $project"
    load_config
    PROJECT="$PROJECT_NAME"

    log "Starting AEGIS-X pipeline for $PROJECT_NAME [Mode: $SCAN_MODE]"

    check_deps
    run_passive
    run_active
    run_screenshots
    run_vuln_scan

    if [[ "$SCAN_MODE" == "ctf" ]]; then
        run_ctf_mode
    fi

    generate_report
    upload_reports
}

# ------------------------ CLI -----------------------------------------------
main() {
    local cmd="${1:-}"; shift || true
    case "$cmd" in
        init)
            [[ -z "${1:-}" || -z "${2:-}" || -z "${3:-}" ]] && err "Usage: $0 init <project> <domain> <mode:bugbounty|pentest|ctf>"
            scaffold_project "$1" "$2" "$3"
            ;;
        run)
            [[ -z "${1:-}" ]] && err "Usage: $0 run <project>"
            run_pipeline "$1"
            ;;
        report)
            [[ -z "${1:-}" ]] && err "Usage: $0 report <project>"
            PROJECT_DIR="$BASE_DIR/$1"; load_config; generate_report
            ;;
        config)
            [[ -z "${1:-}" ]] && err "Usage: $0 config <project>"
            cat "$BASE_DIR/$1/config.env"
            ;;
        test-notify)
            [[ -z "${1:-}" ]] && err "Usage: $0 test-notify <project>"
            PROJECT_DIR="$BASE_DIR/$1"; test_notify
            ;;
        *)
            cat <<EOF
AEGIS-X v$VERSION — Autonomous Security Framework

Usage:
  $0 init <name> <domain> <mode>    Create new project
  $0 run <name>                     Run full pipeline (resumes if interrupted)
  $0 report <name>                  Generate HTML report
  $0 config <name>                  View project config
  $0 test-notify <name>             Send test notification

Modes: bugbounty | pentest | ctf
Projects dir: $BASE_DIR
EOF
            ;;
    esac
}

main "$@"
