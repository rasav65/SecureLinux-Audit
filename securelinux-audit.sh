#!/bin/bash -p
# SecureLinux-Audit check-only CLI (только проверка; код изменений отсутствует физически)
# STATUS=RELEASE
# PRODUCT=SecureLinux-Audit
# VARIANT=check-only
# VERSION=1.0.9
# PRODUCT_CLI=product-cli-v1
# CONTROL_MANIFEST_SHA256=5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39
# ADAPTER_REGISTRY_SHA256=c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8
# TARGET_FAMILY_ID=linux-x86_64-supported-v1
# PLATFORM_MATRIX_SHA256=efc7436850d1ae92df0f36b33e86663728a9fb3643ba3be8cbcaf40b0c9490d7

set -u

slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE() {
  local _slp_passwd='/etc/passwd'
  local _slp_shadow='/etc/shadow'
  local _slp_line _slp_user _slp_rest _slp_pwd _slp_colons _slp_vrc
  local _slp_passwd_text _slp_shadow_text
  local _slp_accounts=0 _slp_empty=0
  local -a _slp_passwd_lines=() _slp_shadow_lines=()
  local -A _slp_shadow_seen=() _slp_shadow_pwd=() _slp_passwd_seen=()
  if [[ -L "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:symlink" "ERROR"
    return 0
  fi
  if [[ -L "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:unreadable" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:unreadable" "ERROR"
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 && "$_slp_v_byte" != 0d ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_passwd" _slp_passwd_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-bytes" "ERROR"; fi
    return 0
  fi
  _slp_load_text "$_slp_shadow" _slp_shadow_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-bytes" "ERROR"; fi
    return 0
  fi
  _slp_rest=$_slp_shadow_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=""; fi
    _slp_shadow_lines+=("$_slp_line")
  done
  _slp_rest=$_slp_passwd_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=""; fi
    _slp_passwd_lines+=("$_slp_line")
  done
  if (( ${#_slp_passwd_lines[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-file" "ERROR"
    return 0
  fi
  if (( ${#_slp_shadow_lines[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:empty-file" "ERROR"
    return 0
  fi
  for _slp_line in "${_slp_shadow_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:empty-record" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 8 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-fields" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    _slp_rest=${_slp_line#*:}
    _slp_pwd=${_slp_rest%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:duplicate-account" "ERROR"; return 0; }
    _slp_shadow_seen["$_slp_user"]=1
    _slp_shadow_pwd["$_slp_user"]=$_slp_pwd
  done
  for _slp_line in "${_slp_passwd_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-record" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 6 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-fields" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_passwd_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:duplicate-account" "ERROR"; return 0; }
    _slp_passwd_seen["$_slp_user"]=1
    [[ -n ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:missing-shadow-account" "ERROR"; return 0; }
    _slp_pwd=${_slp_shadow_pwd["$_slp_user"]}
    ((_slp_accounts+=1))
    [[ -n "$_slp_pwd" ]] || ((_slp_empty+=1))
  done
  (( _slp_accounts > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-population" "ERROR"; return 0; }
  if (( _slp_empty == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=0" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=$_slp_empty" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == permitrootlogin ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitrootlogin ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS() {
  local _slp_cid='FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS'
  local _slp_pam='/etc/pam.d/su'
  local _slp_group='/etc/group'
  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_type _slp_gid='' _slp_members='' _slp_name _slp_pam_text _slp_group_text _slp_rest
  local _slp_parent= _slp_pam_field _slp_wheel_field _slp_root_field _slp_comp _slp_stat_out
  local _slp_pam_absent=0 _slp_group_absent=0
  local -a _slp_tok=() _slp_members_arr=()
  local -A _slp_actual=()
  local _slp_exact=0 _slp_nouid=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_midx=0 _slp_i=0 _slp_vrc=0 _slp_hazard=0

  _slp_name_has_forbidden_separator() {
    local _slp_n=$1
    case "$_slp_n" in
      *' '*|*$'\t'*|*$'\r'*|*$'\v'*|*$'\f'*|*$'\x7f'*|*:*|*','*|*'#'*) return 0 ;;
      *$'\xc2\x85'*|*$'\xc2\xa0'*|*$'\xe1\x9a\x80'*|*$'\xe2\x80\x80'*|*$'\xe2\x80\x81'*|*$'\xe2\x80\x82'*|*$'\xe2\x80\x83'*|*$'\xe2\x80\x84'*|*$'\xe2\x80\x85'*|*$'\xe2\x80\x86'*|*$'\xe2\x80\x87'*|*$'\xe2\x80\x88'*|*$'\xe2\x80\x89'*|*$'\xe2\x80\x8a'*|*$'\xe2\x80\xa8'*|*$'\xe2\x80\xa9'*|*$'\xe2\x80\xaf'*|*$'\xe2\x81\x9f'*|*$'\xe3\x80\x80'*) return 0 ;;
    esac
    return 1
  }

  if [[ -L "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:symlink\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ -L "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:symlink\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -e "$_slp_pam" ]]; then
    _slp_parent=${_slp_pam%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    [[ -d $_slp_parent && -x $_slp_parent ]] || {
      printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"
      return 0
    }
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_pam" 2>&1)
    if (( $? == 0 )) || [[ $_slp_stat_out != *': No such file or directory' ]]; then
      printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"
      return 0
    fi
    _slp_pam_absent=1
  fi
  if [[ ! -e "$_slp_group" ]]; then
    _slp_parent=${_slp_group%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    [[ -d $_slp_parent && -x $_slp_parent ]] || {
      printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"
      return 0
    }
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_group" 2>&1)
    if (( $? == 0 )) || [[ $_slp_stat_out != *': No such file or directory' ]]; then
      printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"
      return 0
    fi
    _slp_group_absent=1
  fi
  if (( _slp_pam_absent || _slp_group_absent )); then
    printf 'SLP-CHECK-V1\t%s\tNOT_FOUND\t-\tFAIL\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:invalid-type\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -r "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:unreadable\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-type\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -r "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:unreadable\tERROR\n' "$_slp_cid"
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
        _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_pam" _slp_pam_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tpam:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi
  _slp_load_text "$_slp_group" _slp_group_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi

  _slp_rest=$_slp_pam_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    _slp_line=${_slp_line%%#*}
    if [[ "$_slp_line" == *\\ ]]; then
      _slp_logical+=${_slp_line%\\}
      continue
    fi
    _slp_logical+="$_slp_line"
    _slp_trim=${_slp_logical#"${_slp_logical%%[!$' \t']*}"}
    _slp_trim=${_slp_trim%"${_slp_trim##*[!$' \t']}"}
    _slp_logical=''
    [[ -n "$_slp_trim" ]] || continue
    read -r -a _slp_tok <<< "$_slp_trim"
    if [[ "${_slp_tok[0]}" == @include ]]; then
      (( ${#_slp_tok[@]} == 2 )) || { _slp_error=1; break; }
      (( _slp_exact > 0 )) || _slp_hazard=1
      continue
    fi
    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }
    _slp_type=${_slp_tok[0],,}
    _slp_type=${_slp_type#-}
    _slp_control=${_slp_tok[1],,}
    if (( _slp_exact == 0 )) && [[ "$_slp_type" == auth ]]; then
      if [[ "${_slp_tok[0],,}" == auth && "$_slp_control" == sufficient && ${#_slp_tok[@]} -eq 3 && "${_slp_tok[2]}" == pam_rootok.so ]]; then
        :
      elif [[ "$_slp_control" == sufficient || "$_slp_control" == include || "$_slp_control" == substack || "$_slp_control" == \[* ]]; then
        _slp_hazard=1
      fi
    fi
    _slp_midx=2
    if [[ "$_slp_control" == \[* ]]; then
      _slp_midx=0
      for ((_slp_i=1; _slp_i<${#_slp_tok[@]}; _slp_i++)); do
        if [[ "${_slp_tok[_slp_i]}" == *\] ]]; then _slp_midx=$((_slp_i+1)); break; fi
      done
      (( _slp_midx > 0 && _slp_midx < ${#_slp_tok[@]} )) || { _slp_error=1; break; }
    fi
    _slp_module=${_slp_tok[_slp_midx]}
    if [[ "${_slp_module##*/}" == pam_wheel.so ]]; then
      if [[ "${_slp_tok[0],,}" == auth && "${_slp_tok[1],,}" == required && "$_slp_module" == pam_wheel.so ]]; then
        if (( ${#_slp_tok[@]} == 4 )) && [[ "${_slp_tok[3]}" == use_uid ]]; then
          ((_slp_exact+=1))
        else
          ((_slp_nouid+=1))
          for ((_slp_i=3; _slp_i<${#_slp_tok[@]}; _slp_i++)); do
            if [[ "${_slp_tok[_slp_i]}" == use_uid ]]; then ((_slp_nouid-=1)); ((_slp_other+=1)); break; fi
          done
        fi
      else
        ((_slp_other+=1))
      fi
    fi
  done
  [[ -z "$_slp_logical" ]] || _slp_error=1
  if (( _slp_error || _slp_other > 0 || (_slp_hazard && _slp_exact > 0) || (_slp_nouid > 0 && _slp_exact > 0) )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:ambiguous-stack\tERROR\n' "$_slp_cid"
    return 0
  fi

  _slp_rest=$_slp_group_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    [[ "$_slp_line" == wheel:* ]] || continue
    ((_slp_wheel+=1))
    if [[ "$_slp_line" =~ ^wheel:([^:]*):([0-9]+):([^:]*)$ ]]; then
      _slp_gid=${BASH_REMATCH[2]}
      _slp_members=${BASH_REMATCH[3]}
    else
      _slp_error=1
    fi
  done
  if (( _slp_error || _slp_wheel > 1 )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-record\tERROR\n' "$_slp_cid"
    return 0
  fi
  if (( _slp_wheel == 1 )) && [[ -n "$_slp_members" ]]; then
    if [[ "$_slp_members" == ,* || "$_slp_members" == *, || "$_slp_members" == *,,* ]]; then _slp_error=1; fi
    IFS=',' read -r -a _slp_members_arr <<< "$_slp_members"
    for _slp_name in "${_slp_members_arr[@]}"; do
      if [[ -z "$_slp_name" ]] || _slp_name_has_forbidden_separator "$_slp_name" || [[ -n "${_slp_actual[$_slp_name]+x}" ]]; then _slp_error=1; break; fi
      _slp_actual["$_slp_name"]=1
    done
  fi
  if (( _slp_error )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-members\tERROR\n' "$_slp_cid"
    return 0
  fi

  if (( _slp_exact > 0 )); then _slp_pam_field=present; elif (( _slp_nouid > 0 )); then _slp_pam_field=no-use_uid; else _slp_pam_field=absent; fi
  if (( _slp_wheel == 1 )); then printf -v _slp_wheel_field 'gid %s' "$_slp_gid"; else _slp_wheel_field=absent; fi
  if [[ -n "${_slp_actual[root]+x}" ]]; then _slp_root_field=member; else _slp_root_field=missing; fi
  if [[ $_slp_pam_field == present && $_slp_wheel_field != absent && $_slp_root_field == member ]]; then _slp_comp=PASS; else _slp_comp=FAIL; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_wheel=%s;wheel=%s;root=%s\t%s\n' "$_slp_cid" "$_slp_pam_field" "$_slp_wheel_field" "$_slp_root_field" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY() {
  local _slp_cid='FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/etc/sudoers' '/usr/sbin/visudo' '/usr/bin/cvtsudoers' <<'SLP_SUDOERS_POLICY_PY'
import hashlib, json, os, stat, subprocess, sys
from pathlib import Path

sudoers_path = Path(sys.argv[1])
visudo_path = sys.argv[2]
cvtsudoers_path = sys.argv[3]
ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def resolve_cvtsudoers(primary):
    # Ubuntu 26.04 with sudo-rs active: package sudo installs cvtsudoers as cvtsudoers.ws.
    if os.path.lexists(primary):
        return primary
    fallback = primary + ".ws"
    try:
        st = os.stat(fallback)
    except FileNotFoundError:
        return primary
    except Exception:
        error("cvtsudoers:fallback-stat-failed")
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
        error("cvtsudoers:untrusted-fallback")
    return fallback


def stock_rule(invoker, runas_group):
    spec = {"runasusers": [{"username": "ALL"}]}
    if runas_group:
        spec["runasgroups"] = [{"usergroup": "ALL"}]
    # cvtsudoers reports the command ALL with its implied SETENV tag.
    spec["Options"] = [{"setenv": True}]
    spec["Commands"] = [{"command": "ALL"}]
    return {"User_List": [invoker], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [spec]}


# The only admissible user specifications: the rules a Debian-family installer
# writes.  Group membership and Defaults are not evaluated.
STOCK_RULES = frozenset(json.dumps(rule, sort_keys=True) for rule in (
    stock_rule({"username": "root"}, True),     # root ALL=(ALL:ALL) ALL
    stock_rule({"usergroup": "sudo"}, True),    # %sudo ALL=(ALL:ALL) ALL
    stock_rule({"usergroup": "admin"}, False),  # %admin ALL=(ALL) ALL
))


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular_bytes(path, domain):
    try:
        first = os.lstat(path)
    except Exception:
        error(domain + ":lstat-failed")
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error(domain + ":invalid-type")
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error(domain + ":read-failed")
    if obj_state(first) != obj_state(second):
        error(domain + ":changed-during-check")
    return obj_state(first), raw


def policy_snapshot():
    # The sudoers pathset is the closure that visudo reports after validating the
    # active tree; no reviewed-policy file is read.  Identities and bytes of that
    # pathset are compared between the two policy observations of one check.
    try:
        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, check=False)
    except Exception:
        error("visudo:execution-failed")
    if proc.returncode != 0:
        error("visudo:validation-failed")
    if not proc.stdout:
        error("visudo:invalid-output")
    if b"\x00" in proc.stdout or b"\r" in proc.stdout:
        error("visudo:invalid-bytes")
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("visudo:invalid-bytes")
    closure = []
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error("visudo:invalid-output")
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in closure:
            error("visudo:invalid-output")
        closure.append(path_text)
    if not closure or str(sudoers_path) not in closure:
        error("visudo:invalid-output")
    out = []
    for path_text in sorted(closure):
        state, raw = stable_regular_bytes(Path(path_text), "sudoers")
        out.append((path_text, state, hashlib.sha256(raw).hexdigest()))
    return tuple(out)


def cvt_snapshot():
    try:
        proc = subprocess.run(
            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, check=False,
        )
    except Exception:
        error("cvtsudoers:execution-failed")
    if proc.returncode != 0 or proc.stderr:
        error("cvtsudoers:execution-failed")
    if not proc.stdout:
        error("cvtsudoers:invalid-output")
    if b"\x00" in proc.stdout:
        error("cvtsudoers:invalid-bytes")
    try:
        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))
    except Exception:
        error("cvtsudoers:invalid-output")
    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:
        error("cvtsudoers:invalid-output")
    specs = data.get("User_Specs", [])
    if not isinstance(specs, list):
        error("cvtsudoers:invalid-output")
    return proc.stdout, specs


def count_nonstandard(specs):
    nonstandard = 0
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error("sudo-policy:invalid-user-spec")
        # Canonical JSON keeps JSON true distinct from 1.
        if json.dumps(user_spec, sort_keys=True) not in STOCK_RULES:
            nonstandard += 1
    return nonstandard


cvtsudoers_path = resolve_cvtsudoers(cvtsudoers_path)
policy_before = policy_snapshot()
cvt_before, specs = cvt_snapshot()
nonstandard = count_nonstandard(specs)
policy_after = policy_snapshot()
cvt_after, specs_after = cvt_snapshot()
if policy_after != policy_before or cvt_after != cvt_before:
    error("observation:policy-changed")

print("VALUE\trules=%d;nonstandard=%d\t%s" % (len(specs), nonstandard, "PASS" if nonstandard == 0 else "FAIL"))

SLP_SUDOERS_POLICY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:execution-failed\tERROR\n' "$_slp_cid"; return 0; fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "${_slp_obs#*$'\t'}"; return 0; fi
  IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ "$_slp_kind" != VALUE || -z "$_slp_value" || -n "$_slp_extra" || ( "$_slp_compliance" != PASS && "$_slp_compliance" != FAIL ) ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\t%s\t%s\n' "$_slp_cid" "$_slp_value" "$_slp_compliance"
}

slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE() {
  local _slp_path='/etc/group'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE() {
  local _slp_path='/etc/passwd'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX() {
  local _slp_path='/etc/shadow'
  local _slp_expected='0640'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra='' _slp_attempt=0
  while :; do
  _slp_attempt=$((_slp_attempt + 1))
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/proc' '/' <<'SLP_RUNTIME_PATHS_PY'
import os, re, stat, sys
from pathlib import Path

proc_root = Path(sys.argv[1])
parent_stop = Path(sys.argv[2])

MAP_ADDRESS = re.compile(r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$")
MAP_PERMS = re.compile(r"^[r-][w-][x-][ps]$")
MAP_OFFSET = re.compile(r"^[0-9A-Fa-f]+$")
MAP_DEVICE = re.compile(r"^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$")
ASCII_DECIMAL = re.compile(r"^[0-9]+$")
ASCII_SIGNED_DECIMAL = re.compile(r"^-?[0-9]+$")
PROC_PROCESSES = re.compile(r"^processes[ \t]+([0-9]+)$")
OCTAL = set("01234567")
PF_KTHREAD = 0x00200000


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_stat_fields(pid):
    try:
        raw = (pid / "stat").read_text(encoding="ascii", errors="strict")
    except FileNotFoundError:
        return None
    except Exception:
        error("proc-stat:read-failed")
    if "\x00" in raw or "\r" in raw:
        error("proc-stat:invalid-bytes")
    if raw.endswith("\n"):
        body = raw[:-1]
    else:
        body = raw
    if not body or "\n" in body or "\t" in body or "\v" in body or "\f" in body:
        error("proc-stat:invalid-layout")
    prefix = pid.name + " ("
    if not body.startswith(prefix):
        error("proc-stat:invalid-prefix")
    close = body.rfind(")")
    if close < len(prefix) - 1 or close + 1 >= len(body) or body[close + 1] != " ":
        error("proc-stat:invalid-command-field")
    fields = body[close + 2:].split(" ")
    if len(fields) != 50 or any(field == "" for field in fields):
        error("proc-stat:invalid-field-count")
    state = fields[0]
    if len(state) != 1 or not state.isascii() or not state.isalpha():
        error("proc-stat:invalid-state")
    for value in fields[1:]:
        if ASCII_SIGNED_DECIMAL.fullmatch(value) is None:
            error("proc-stat:invalid-number")
    if ASCII_DECIMAL.fullmatch(fields[19]) is None:
        error("proc-stat:invalid-starttime")
    return fields


def read_start(pid):
    fields = read_stat_fields(pid)
    if fields is None:
        return None
    return fields[19]


def read_process_counter():
    try:
        text = (proc_root / "stat").read_text(encoding="ascii", errors="strict")
    except Exception:
        error("proc-counter:read-failed")
    if "\x00" in text or "\r" in text:
        error("proc-counter:invalid-bytes")
    values = []
    for line in text.splitlines():
        if not line.startswith("processes"):
            continue
        match = PROC_PROCESSES.fullmatch(line)
        if match is None:
            error("proc-counter:invalid-record")
        values.append(int(match.group(1), 10))
    if len(values) != 1:
        error("proc-counter:invalid-record-count")
    return values[0]


def population_snapshot():
    try:
        entries = sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    except Exception:
        error("proc-population:scan-failed")
    if not entries:
        error("proc-population:empty")
    snap = {}
    for pid in entries:
        start = read_start(pid)
        if start is None:
            error("proc-population:process-disappeared")
        snap[pid.name] = start
    return snap


def classify_no_exe(pid, expected_start):
    try:
        status = (pid / "status").read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        error("proc-status:invalid-bytes")
    except Exception:
        error("proc-status:read-failed")
    if "\x00" in status or "\r" in status:
        error("proc-status:invalid-bytes")
    kthread = None
    state = None
    for line in status.splitlines():
        if line.startswith("Kthread:"):
            kthread = line.split(":", 1)[1].strip() == "1"
        elif line.startswith("State:"):
            value = line.split(":", 1)[1].strip()
            state = value[:1] if value else None
    if kthread is None:
        # No Kthread line in status (observed on 5.15 and 6.1): PF_KTHREAD in stat flags.
        fields = read_stat_fields(pid)
        if fields is None:
            error("proc-stat:excluded-classification-vanished")
        if ASCII_DECIMAL.fullmatch(fields[6]) is None:
            error("proc-stat:invalid-flags")
        kthread = (int(fields[6], 10) & PF_KTHREAD) != 0
    if not (kthread or state == "Z"):
        error("proc-status:no-exe-unclassified")
    end = read_start(pid)
    if end is None or end != expected_start:
        error("proc-stat:excluded-classification-changed")
    return "excluded"


def decode_proc_path(raw):
    out = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 3 >= len(raw):
            error("proc:invalid-path-escape")
        digits = raw[i + 1:i + 4]
        if any(c not in OCTAL for c in digits):
            error("proc:invalid-path-escape")
        value = int(digits, 8)
        if value == 0:
            error("proc:invalid-path-escape")
        out.append(chr(value))
        i += 4
    return "".join(out)


def obj_state(st):
    return (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        st.st_gid,
        stat.S_IMODE(st.st_mode),
        st.st_ctime_ns,
    )


def within_stop(real):
    if parent_stop == Path("/"):
        return
    try:
        Path(real).relative_to(parent_stop)
    except ValueError:
        error("path:outside-scope")


def check_path(path_text, file_records, file_states, parent_records, path_set, expected_mapping=None):
    if not path_text.startswith("/") or "\x00" in path_text:
        error("path:invalid-absolute")
    try:
        source_lstat = os.lstat(path_text)
        real = os.path.realpath(path_text)
    except Exception:
        error("path:resolve-failed")
    if not real.startswith("/"):
        error("path:invalid-resolved")
    within_stop(real)
    try:
        fst = os.stat(real, follow_symlinks=True)
    except Exception:
        error("path:stat-failed")
    if not stat.S_ISREG(fst.st_mode):
        error("path:invalid-type")
    if expected_mapping is not None:
        map_major, map_minor, map_inode = expected_mapping
        try:
            actual_major = os.major(fst.st_dev)
            actual_minor = os.minor(fst.st_dev)
        except Exception:
            error("path:device-id-failed")
        if (actual_major, actual_minor, fst.st_ino) != (map_major, map_minor, map_inode):
            error("path:mapping-mismatch")
    source_state = obj_state(source_lstat)
    target_state = obj_state(fst)
    record = (real, source_state, target_state)
    old = file_records.get(path_text)
    if old is not None and old != record:
        error("path:repeat-record-changed")
    file_records[path_text] = record
    identity = (fst.st_dev, fst.st_ino)
    old_state = file_states.get(identity)
    if old_state is not None and old_state != target_state:
        error("path:identity-state-changed")
    file_states[identity] = target_state
    path_set.add(real)

    cur = Path(real).parent
    stop = parent_stop
    while True:
        try:
            dst = os.stat(cur, follow_symlinks=True)
        except Exception:
            error("parent:stat-failed")
        if not stat.S_ISDIR(dst.st_mode):
            error("parent:invalid-type")
        state = obj_state(dst)
        old_dir = parent_records.get(str(cur))
        if old_dir is not None and old_dir != state:
            error("parent:repeat-snapshot-changed")
        parent_records[str(cur)] = state
        if cur == stop:
            break
        if cur == cur.parent:
            if stop != cur:
                error("path:outside-scope")
            break
        if stop != Path("/"):
            try:
                cur.relative_to(stop)
            except ValueError:
                error("path:outside-scope")
        cur = cur.parent
    return identity


def parse_maps(pid):
    try:
        text = (pid / "maps").read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        error("proc-maps:invalid-bytes")
    except Exception:
        error("proc-maps:read-failed")
    if "\x00" in text or "\r" in text:
        error("proc-maps:invalid-bytes")
    mapped_exec = []
    saw_line = False
    for line in text.splitlines():
        if not line:
            continue
        saw_line = True
        parts = line.split(None, 5)
        if len(parts) not in (5, 6):
            error("proc-maps:invalid-fields")

        address_text, perms, offset_text, device_text, inode_text = parts[:5]
        address = MAP_ADDRESS.fullmatch(address_text)
        if address is None:
            error("proc-maps:invalid-address")
        start = int(address.group(1), 16)
        end = int(address.group(2), 16)
        if start >= end:
            error("proc-maps:invalid-address-range")
        if not MAP_PERMS.fullmatch(perms):
            error("proc-maps:invalid-permissions")
        if not MAP_OFFSET.fullmatch(offset_text):
            error("proc-maps:invalid-offset")
        offset = int(offset_text, 16)
        device = MAP_DEVICE.fullmatch(device_text)
        if device is None:
            error("proc-maps:invalid-device")
        dev_major = int(device.group(1), 16)
        dev_minor = int(device.group(2), 16)
        if ASCII_DECIMAL.fullmatch(inode_text) is None:
            error("proc-maps:invalid-inode")
        inode = int(inode_text, 10)

        if len(parts) == 5:
            if inode != 0:
                error("proc-maps:anonymous-inode")
            continue

        raw_path = parts[5]
        if raw_path.startswith("[") and raw_path.endswith("]"):
            if inode != 0:
                error("proc-maps:pseudo-inode")
            continue

        path = decode_proc_path(raw_path)
        if path.startswith("anon_inode:") and perms[2] != "x":
            continue
        # Неисполняемое отображение с пометкой (deleted) (например, разделяемая память System V
        # /SYSV<key>) вне популяции исполняемых файлов (решение пользователя 07.10.2026).
        if path.endswith(" (deleted)") and perms[2] != "x":
            continue
        if path.endswith(" (deleted)"):
            error("proc-maps:deleted-path")
        if not path.startswith("/"):
            error("proc-maps:nonabsolute-path")
        if perms[2] != "x":
            continue
        if inode == 0:
            error("proc-maps:executable-zero-inode")
        mapped_exec.append((path, start, end, offset, dev_major, dev_minor, inode))

    if not saw_line or not mapped_exec:
        error("proc-maps:empty-executable-population")
    return mapped_exec


def read_exe(pid):
    try:
        target = os.readlink(pid / "exe")
        exe_stat = os.stat(pid / "exe", follow_symlinks=True)
    except FileNotFoundError:
        return None
    except Exception:
        error("proc-exe:read-failed")
    if target.endswith(" (deleted)") or not target.startswith("/") or "\x00" in target:
        error("proc-exe:invalid-target")
    if not stat.S_ISREG(exe_stat.st_mode):
        error("proc-exe:invalid-type")
    return target, obj_state(exe_stat)


def recheck_files(file_records):
    for source, (real, source_state, target_state) in file_records.items():
        try:
            now_source = os.lstat(source)
            now_real = os.path.realpath(source)
            now_target = os.stat(now_real, follow_symlinks=True)
        except Exception:
            error("path:recheck-stat-failed")
        if now_real != real:
            error("path:recheck-resolved-target-changed")
        if obj_state(now_source) != source_state or obj_state(now_target) != target_state:
            error("path:recheck-snapshot-changed")


def recheck_parents(parent_records):
    for path, expected in parent_records.items():
        try:
            now = os.stat(path, follow_symlinks=True)
        except Exception:
            error("parent:recheck-stat-failed")
        if not stat.S_ISDIR(now.st_mode):
            error("parent:recheck-invalid-type")
        if obj_state(now) != expected:
            error("parent:recheck-snapshot-changed")


def recheck_processes(process_records, excluded_records):
    for pid_name, record in process_records.items():
        expected_start, expected_target, expected_exe_state, expected_maps = record
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error("proc-stat:recheck-starttime-changed")
        current_exe = read_exe(pid)
        if current_exe is None:
            error("proc-exe:recheck-missing")
        target, exe_state = current_exe
        if target != expected_target or exe_state != expected_exe_state:
            error("proc-exe:recheck-changed")
        current_maps = tuple(parse_maps(pid))
        if current_maps != expected_maps:
            error("proc-maps:recheck-changed")
        end = read_start(pid)
        if end is None or end != expected_start:
            error("proc-stat:recheck-endtime-changed")

    for pid_name, expected_start in excluded_records.items():
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error("proc-stat:excluded-recheck-changed")
        if read_exe(pid) is not None:
            error("proc-exe:excluded-reappeared")
        classify_no_exe(pid, expected_start)


try:
    pst = os.lstat(proc_root)
except Exception:
    error("proc-root:lstat-failed")
if not stat.S_ISDIR(pst.st_mode) or stat.S_ISLNK(pst.st_mode):
    error("proc-root:invalid-type")
try:
    sst = os.stat(parent_stop)
except Exception:
    error("parent-stop:stat-failed")
if not stat.S_ISDIR(sst.st_mode):
    error("parent-stop:invalid-type")

fork_counter = read_process_counter()
initial_population = population_snapshot()
file_records = {}
file_states = {}
path_set = set()
parent_records = {}
process_records = {}
excluded_records = {}
processes = 0
libraries_seen = 0
excluded = 0

for pid_name, expected_start in sorted(initial_population.items(), key=lambda item: int(item[0])):
    pid = proc_root / pid_name
    start = read_start(pid)
    if start is None or start != expected_start:
        error("proc-stat:initial-starttime-changed")

    exe_observation = read_exe(pid)
    if exe_observation is None:
        classify_no_exe(pid, expected_start)
        excluded_records[pid_name] = expected_start
        excluded += 1
        continue

    target, exe_state = exe_observation
    exe_identity = check_path(target, file_records, file_states, parent_records, path_set)
    if (exe_state[0], exe_state[1]) != exe_identity:
        error("proc-exe:identity-mismatch")

    mapped_records = tuple(parse_maps(pid))
    mapped_ids = set()
    for path, map_start, map_end, map_offset, map_major, map_minor, map_inode in mapped_records:
        mapped_ids.add(
            check_path(
                path,
                file_records,
                file_states,
                parent_records,
                path_set,
                expected_mapping=(map_major, map_minor, map_inode),
            )
        )

    end = read_start(pid)
    if end is None or end != expected_start:
        error("proc-stat:initial-endtime-changed")

    process_records[pid_name] = (expected_start, target, exe_state, mapped_records)
    processes += 1
    libraries_seen += len(mapped_ids - {exe_identity})

if processes == 0 or not file_states:
    error("proc-population:empty-observation")

mid_population = population_snapshot()
if mid_population != initial_population:
    error("pid-population:mid-snapshot-changed")
if read_process_counter() != fork_counter:
    error("proc-counter:mid-snapshot-changed")

recheck_processes(process_records, excluded_records)
recheck_files(file_records)
recheck_parents(parent_records)

final_population = population_snapshot()
if final_population != initial_population:
    error("pid-population:final-snapshot-changed")
if read_process_counter() != fork_counter:
    error("proc-counter:final-snapshot-changed")

file_violations = sum(1 for state in file_states.values() if state[4] & 0o022)
parent_violations = 0
parent_ambiguous = 0
for state in parent_records.values():
    uid, mode = state[2], state[4]
    # Directory entry mutation requires both write and search (execute) on the
    # directory. A non-root owner or world class with wx proves unprivileged
    # writability. Group-class wx alone does not identify which principals
    # receive it (owning-group membership / POSIX ACL semantics), so it is
    # fail-closed ambiguity rather than a source-level FAIL.
    if uid != 0 and (mode & 0o300) == 0o300:
        parent_violations += 1
    if (mode & 0o003) == 0o003:
        parent_violations += 1
    if (mode & 0o030) == 0o030:
        parent_ambiguous += 1

if parent_violations == 0 and parent_ambiguous:
    error("parent:group-write-ambiguous")

value = (
    f"pids={processes};files={len(file_states)};paths={len(path_set)};parents={len(parent_records)};"
    f"libraries={libraries_seen};forks={fork_counter};vanished=0;excluded={excluded};"
    f"file_violations={file_violations};parent_violations={parent_violations}"
)
compliance = "PASS" if file_violations == 0 and parent_violations == 0 else "FAIL"
print("VALUE\t" + value + "\t" + compliance)
SLP_RUNTIME_PATHS_PY
  )
  _slp_rc=$?
  if (( _slp_rc == 0 && _slp_attempt < 3 )) && [[ $_slp_obs == ERROR$'\t'* ]]; then
    case ${_slp_obs#ERROR$'\t'} in
      proc-population:process-disappeared|proc-status:no-exe-unclassified|proc-stat:initial-starttime-changed|proc-stat:initial-endtime-changed|proc-stat:excluded-classification-vanished|proc-stat:excluded-classification-changed|pid-population:mid-snapshot-changed|proc-counter:mid-snapshot-changed|proc-stat:recheck-starttime-changed|proc-exe:recheck-missing|proc-stat:recheck-endtime-changed|proc-stat:excluded-recheck-changed|proc-exe:excluded-reappeared|pid-population:final-snapshot-changed|proc-counter:final-snapshot-changed) command /usr/bin/sleep 1; continue ;;
    esac
  fi
  break
  done
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'	'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "${_slp_obs#*$'	'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/' '0' <<'SLP_CRON_PATHS_PY'
import hashlib, os, re, shlex, stat, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
logical_root_uid = int(sys.argv[2], 10)
ASCII_DECIMAL = re.compile(r"^[0-9]+$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CROND_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.S)
SCHEDULE_FIELD = re.compile(r"^[A-Za-z0-9*?,/\-]+$")
SPECIAL = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
SAFE_BUILTINS = {"cd", "test", "[", ":", "true", "false", "echo", "printf", "pwd"}
UNSUPPORTED_COMMANDS = {
    ".", "source", "eval", "exec", "command", "export", "unset", "read", "set", "shift", "trap",
    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",
    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",
    "busybox", "toybox",
    "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",
    "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",
    "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
    "docker", "podman", "systemd-nspawn", "machinectl",
}
INTERPRETER_NAME = re.compile(
    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\.[0-9]+)*)?|"
    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"
    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"
)
CONTROL_OPS = {"&&", "||", ";", "|", "&", "(", ")"}
# No PATH= in the crontab: every executable match in these directories is a target.
DEFAULT_SEARCH_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin")
FIND_EXEC_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir"}
UNSUPPORTED_COMPOUND = {"while", "until", "for", "case", "select", "function", "coproc", "do", "done", "esac", "[[", "]]"}
FD_WORDS = {"1", "2"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def map_abs(path_text):
    if not isinstance(path_text, str) or not path_text.startswith("/") or "\x00" in path_text or "\r" in path_text or "\n" in path_text:
        error("path:invalid-absolute")
    return fsroot / path_text.lstrip("/")


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular(path, allow_symlink=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        return None
    except Exception:
        error("file:lstat-failed")
    if stat.S_ISLNK(first.st_mode):
        if not allow_symlink:
            error("file:symlink")
        try:
            real = os.path.realpath(path)
            target = os.stat(real, follow_symlinks=True)
            second = os.lstat(path)
        except Exception:
            error("file:resolve-failed")
        if obj_state(first) != obj_state(second):
            error("file:changed-during-check")
        if not stat.S_ISREG(target.st_mode):
            error("file:invalid-type")
        return (str(path), real, obj_state(first), obj_state(target))
    if not stat.S_ISREG(first.st_mode):
        error("file:invalid-type")
    try:
        second = os.lstat(path)
    except Exception:
        error("file:lstat-failed")
    if obj_state(first) != obj_state(second):
        error("file:changed-during-check")
    return (str(path), str(path), obj_state(first), obj_state(first))


def stable_text(path, optional=False, allow_symlink=False):
    rec = stable_regular(path, allow_symlink=allow_symlink)
    if rec is None:
        if optional:
            return None
        error("file:not-found")
    try:
        raw = path.read_bytes()
        after = stable_regular(path, allow_symlink=allow_symlink)
    except Exception:
        error("file:read-failed")
    if after != rec:
        error("file:changed-during-check")
    if b"\x00" in raw or b"\r" in raw:
        error("file:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("file:invalid-utf8")
    return rec, hashlib.sha256(raw).hexdigest(), text


def stable_dir(path, optional=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:lstat-failed")
    if stat.S_ISLNK(first.st_mode):
        error("directory:symlink")
    if not stat.S_ISDIR(first.st_mode):
        error("directory:invalid-type")
    try:
        names = sorted(os.listdir(path), key=os.fsencode)
        second = os.lstat(path)
    except Exception:
        error("directory:scan-failed")
    if obj_state(first) != obj_state(second):
        error("directory:changed-during-check")
    return obj_state(first), tuple(names)


def stable_search_dir(path, optional):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:lstat-failed")
    if not stat.S_ISLNK(first.st_mode):
        return stable_dir(path, optional=optional)
    try:
        real = os.path.realpath(path)
        target = os.stat(real, follow_symlinks=True)
        second = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:resolve-failed")
    if obj_state(first) != obj_state(second):
        error("directory:changed-during-check")
    if not stat.S_ISDIR(target.st_mode):
        error("directory:invalid-type")
    return obj_state(first), real, obj_state(target)


def parse_passwd():
    observed = stable_text(map_abs("/etc/passwd"), optional=False)
    users = {}
    for line in observed[2].splitlines():
        if not line:
            error("passwd:empty-record")
        parts = line.split(":")
        if len(parts) != 7:
            error("passwd:invalid-fields")
        name, _, uid_text, gid_text, _, home, _ = parts
        if not name:
            error("passwd:invalid-account")
        if name in users:
            error("passwd:duplicate-account")
        if ASCII_DECIMAL.fullmatch(uid_text) is None or ASCII_DECIMAL.fullmatch(gid_text) is None:
            error("passwd:invalid-id")
        if not home.startswith("/"):
            error("passwd:invalid-home")
        users[name] = (int(uid_text), int(gid_text), home)
    if "root" not in users or users["root"][0] != 0:
        error("passwd:invalid-root")
    return observed, users


def parse_env_value(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if any(ch in value for ch in "\x00\r\n`$"):
        error("cron:invalid-environment-value")
    return value


def parse_path_value(raw):
    value = parse_env_value(raw)
    parts = value.split(":")
    if not parts or any(not p.startswith("/") or p == "/" and False for p in parts) or any(p == "" for p in parts):
        error("cron:invalid-path")
    return tuple(parts)


def split_percent(command):
    out = []
    escaped = False
    for ch in command:
        if escaped:
            if ch == "%":
                out.append("%")
            else:
                out.append("\\")
                out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "%":
            break
        out.append(ch)
    if escaped:
        out.append("\\")
    result = "".join(out).strip()
    if not result:
        error("cron:empty-command")
    return result


def cron_job(line, system_file, owner_user, users):
    parts = line.split()
    if not parts:
        error("cron:empty-record")
    if parts[0].startswith("@"):
        if parts[0] not in SPECIAL:
            error("cron:invalid-schedule")
        needed = 3 if system_file else 2
        if len(parts) < needed:
            error("cron:invalid-fields")
        user = parts[1] if system_file else owner_user
        command = line.split(None, 2 if system_file else 1)[2 if system_file else 1]
    else:
        if len(parts) < (7 if system_file else 6):
            error("cron:invalid-fields")
        for field in parts[:5]:
            if SCHEDULE_FIELD.fullmatch(field) is None:
                error("cron:invalid-schedule")
        user = parts[5] if system_file else owner_user
        command = line.split(None, 6 if system_file else 5)[6 if system_file else 5]
    if user not in users:
        error("cron:unknown-user")
    return user, split_percent(command)


def lex_command(command):
    if any(ch in command for ch in "\x00\r\n`$"):
        error("command:invalid-bytes")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except Exception:
        error("command:parse-failed")
    if not tokens:
        error("command:empty")
    for tok in tokens:
        if ("<" in tok or ">" in tok) and tok not in {">", ">&"}:
            error("command:unsupported-redirection")
    return tokens


def resolve_root_command(word, path_env, uid, dir_records):
    if "/" in word:
        if not word.startswith("/"):
            error("command:relative-path")
        return [word]
    if uid != 0:
        error("command:unresolved-name")
    search = DEFAULT_SEARCH_PATH if path_env is None else path_env
    found = []
    for d in search:
        drec = stable_search_dir(map_abs(d), optional=path_env is None)
        dir_records[("path", d)] = drec
        if drec is None:
            continue
        candidate_text = d.rstrip("/") + "/" + word
        candidate = map_abs(candidate_text)
        try:
            st = os.stat(candidate, follow_symlinks=True)
        except FileNotFoundError:
            continue
        except Exception:
            error("command:stat-failed")
        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:
            if path_env is not None:
                return [candidate_text]
            found.append(candidate_text)
    if not found:
        error("command:not-found")
    return found


def resolved_command_record(path_text):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error("target:not-found")
    target_state = rec[3]
    if target_state[8] != 1:
        error("target:hardlink")
    if (target_state[4] & 0o111) == 0:
        error("target:not-executable")
    canonical_base = os.path.basename(rec[1])
    if not canonical_base or canonical_base in {".", ".."}:
        error("target:invalid-name")
    return rec, canonical_base


def add_target(path_text, targets, allow_nonexec=False):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error("target:not-found")
    target_state = rec[3]
    if not allow_nonexec and (target_state[4] & 0o111) == 0:
        error("target:not-executable")
    previous = targets.get(path_text)
    if previous is not None and previous != rec:
        error("target:changed-during-check")
    targets[path_text] = rec


def expand_run_parts(args, targets, dir_records):
    directory = None
    for arg in args:
        if arg in {"--report", "--verbose"}:
            continue
        if arg.startswith("-"):
            error("run-parts:unsupported-option")
        if directory is not None:
            error("run-parts:ambiguous-directory")
        directory = arg
    if directory is None or not directory.startswith("/"):
        error("run-parts:invalid-directory")
    dpath = map_abs(directory)
    drec = stable_dir(dpath, optional=False)
    dir_records[("run-parts", directory)] = drec
    for name in drec[1]:
        if CROND_NAME.fullmatch(name) is None:
            continue
        child_text = directory.rstrip("/") + "/" + name
        child = map_abs(child_text)
        try:
            st = os.stat(child, follow_symlinks=True)
        except FileNotFoundError:
            error("run-parts:child-not-found")
        except Exception:
            error("run-parts:child-stat-failed")
        if not stat.S_ISREG(st.st_mode):
            continue
        if stat.S_IMODE(st.st_mode) & 0o111:
            add_target(child_text, targets, allow_nonexec=False)


def parse_shell(command, user, users, path_env, targets, dir_records):
    tokens = lex_command(command)
    segments = []
    current = []
    stack = []
    closed = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in {">", ">&"}:
            if i + 1 >= len(tokens):
                error("command:unsupported-redirection")
            sink = tokens[i + 1]
            if not ((tok == ">" and sink == "/dev/null") or (tok == ">&" and sink in FD_WORDS)):
                error("command:unsupported-redirection")
            if len(current) >= 2 and current[-1] in FD_WORDS:
                current.pop()
            if not current:
                error("command:unsupported-redirection")
            i += 2
            continue
        i += 1
        if closed:
            if tok not in CONTROL_OPS or tok == "(":
                error("command:unsupported-grouping")
            closed = False
        if not current:
            if tok in {"(", "{", "if"}:
                stack.append(tok)
                continue
            if tok == "}":
                if not stack or stack[-1] != "{":
                    error("command:unbalanced-group")
                stack.pop()
                closed = True
                continue
            if tok == "then":
                if not stack or stack[-1] not in {"if", "elif"}:
                    error("command:unbalanced-group")
                stack[-1] = "then"
                continue
            if tok in {"elif", "else"}:
                if not stack or stack[-1] != "then":
                    error("command:unbalanced-group")
                stack[-1] = tok
                continue
            if tok == "fi":
                if not stack or stack[-1] not in {"then", "else"}:
                    error("command:unbalanced-group")
                stack.pop()
                closed = True
                continue
            if tok == "!":
                continue
        if tok == ")":
            if current:
                segments.append(current); current = []
            if not stack or stack[-1] != "(":
                error("command:unbalanced-group")
            stack.pop()
            closed = True
            continue
        if tok in CONTROL_OPS:
            if tok == "(":
                error("command:unsupported-grouping")
            if current:
                segments.append(current); current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    if stack or not segments:
        error("command:unbalanced-group")

    uid = users[user][0]
    for seg in segments:
        local_path = path_env
        i = 0
        while i < len(seg) and ASSIGNMENT.fullmatch(seg[i]):
            name, value = seg[i].split("=", 1)
            if name == "PATH":
                local_path = parse_path_value(value)
            i += 1
        if i >= len(seg):
            continue
        command_word = seg[i]
        args = seg[i + 1:]
        if command_word == "exec":
            if not args or args[0].startswith("-") or ASSIGNMENT.fullmatch(args[0]):
                error("command:unsupported-wrapper")
            command_word, args = args[0], args[1:]
        if command_word in SAFE_BUILTINS:
            continue
        # command -v/-V only reports the lookup result and runs nothing.
        if command_word == "command" and len(args) == 2 and args[0] in {"-v", "-V"}:
            continue
        if command_word in UNSUPPORTED_COMPOUND:
            error("command:unsupported-compound")
        # find без -exec/-execdir/-ok/-okdir сам ничего не запускает: цель: сам find
        # (решение пользователя 07.10.2026).
        plain_find = os.path.basename(command_word) == "find" and not FIND_EXEC_ACTIONS.intersection(args)
        if command_word in UNSUPPORTED_COMMANDS and not plain_find:
            error("command:unsupported-wrapper")
        periodic = False
        for resolved in resolve_root_command(command_word, local_path, uid, dir_records):
            _resolved_rec, canonical_base = resolved_command_record(resolved)
            if ((canonical_base in UNSUPPORTED_COMMANDS and not (plain_find and canonical_base == "find"))
                    or INTERPRETER_NAME.fullmatch(canonical_base) is not None):
                error("command:unsupported-execution-chain")
            add_target(resolved, targets, allow_nonexec=False)
            if canonical_base == "run-parts":
                periodic = True
        if periodic:
            expand_run_parts(args, targets, dir_records)


def parse_crontab(path, system_file, owner_user, users, sources, targets, dir_records):
    observed = stable_text(path, optional=False, allow_symlink=False)
    if observed[2] and not observed[2].endswith("\n"):
        error("cron:invalid-line-ending")
    sources[str(path)] = observed[:2]
    path_env = None
    jobs = 0
    for raw_line in observed[2].splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", raw_line)
        if m:
            name, value = m.group(1), m.group(2)
            if not ENV_NAME.fullmatch(name):
                error("cron:invalid-environment-name")
            if name == "PATH":
                path_env = parse_path_value(value)
            elif name == "SHELL":
                if parse_env_value(value) != "/bin/sh":
                    error("cron:unsupported-shell")
            continue
        user, command = cron_job(raw_line, system_file, owner_user, users)
        parse_shell(command, user, users, path_env, targets, dir_records)
        jobs += 1
    return jobs


def discover():
    passwd_obs, users = parse_passwd()
    sources = {str(map_abs("/etc/passwd")): passwd_obs[:2]}
    targets = {}
    dir_records = {}
    jobs = 0
    configs = 0

    etc_dir = stable_dir(map_abs("/etc"), optional=False)
    dir_records[("root", "/etc")] = etc_dir

    crontab_path = map_abs("/etc/crontab")
    if stable_regular(crontab_path, allow_symlink=False) is not None:
        jobs += parse_crontab(crontab_path, True, None, users, sources, targets, dir_records)
        configs += 1

    cron_d_path = map_abs("/etc/cron.d")
    cron_d = stable_dir(cron_d_path, optional=True)
    if cron_d is not None:
        dir_records[("root", "/etc/cron.d")] = cron_d
        for name in cron_d[1]:
            if CROND_NAME.fullmatch(name) is None:
                continue
            cfg = cron_d_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error("cron:config-disappeared")
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != logical_root_uid or stat.S_IMODE(st.st_mode) & 0o022:
                error("cron:config-untrusted")
            jobs += parse_crontab(cfg, True, None, users, sources, targets, dir_records)
            configs += 1

    spool_path = map_abs("/var/spool/cron/crontabs")
    spool = stable_dir(spool_path, optional=True)
    if spool is not None:
        dir_records[("root", "/var/spool/cron/crontabs")] = spool
        for name in spool[1]:
            if name not in users:
                continue
            cfg = spool_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error("cron:spool-disappeared")
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != users[name][0] or stat.S_IMODE(st.st_mode) & 0o022:
                error("cron:spool-untrusted")
            jobs += parse_crontab(cfg, False, name, users, sources, targets, dir_records)
            configs += 1

    # One file reached by several paths (/usr/bin/run-parts and /bin/run-parts on merged /usr)
    # is counted once: identity is dev:ino of the final regular file.
    unique = {rec[3][:2]: rec for rec in targets.values()}
    violations = sum(1 for rec in unique.values() if rec[3][4] & 0o022)
    periodic = sum(1 for key in dir_records if key[0] == "run-parts")
    return sources, targets, dir_records, configs, jobs, periodic, violations


try:
    rst = os.lstat(fsroot)
except Exception:
    error("root:lstat-failed")
if stat.S_ISLNK(rst.st_mode):
    error("root:symlink")
if not stat.S_ISDIR(rst.st_mode):
    error("root:invalid-type")

first = discover()
second = discover()
if first != second:
    error("observation:changed-during-check")
_, targets, _, configs, jobs, periodic, violations = first
value = f"configs={configs};jobs={jobs};targets={len({rec[3][:2] for rec in targets.values()})};periodic_dirs={periodic};violations={violations};ambiguous=0"
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))
SLP_CRON_PATHS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'	'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "${_slp_obs#*$'	'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_4_SUDO_ROOT_COMMAND_FILES_PROTECTION() {
  local _slp_cid='FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION' _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/' '/etc/sudoers' '/usr/sbin/visudo' '/usr/bin/cvtsudoers' '/etc/login.defs' '/etc/adduser.conf' <<'SLP_SUDO_ROOT_FILES_PY'
import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
sudoers_path = Path(sys.argv[2])
visudo_path = sys.argv[3]
cvtsudoers_path = sys.argv[4]
login_defs_path = Path(sys.argv[5])
adduser_conf_path = Path(sys.argv[6])
ALLOWED_COMMAND_KEYS = {"command", "negated", "sha224", "sha256", "sha384", "sha512"}
WILDCARD_CHARS = set("*?[")
# In sudoers a pathname gets a space or a tab only through a backslash before it, and a
# backslash before a line end continues the line.  Without such a backslash in any file
# of the active sudoers closure the first space or tab of a cvtsudoers command string is
# the pathname boundary.
ESCAPED_WHITESPACE = re.compile(rb"\\[ \t\r\n]")
COMMAND_SEPARATOR = re.compile(r"[ \t]+")
UID_RANGE_LINE = re.compile(r"^\s*([A-Z_]+)\s+([0-9]+)\s*$")
CONF_RANGE_LINE = re.compile(r"^\s*([A-Z_]+)\s*=\s*\"?([0-9]+)\"?\s*$")
RANGE_KEY_HEAD = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def resolve_cvtsudoers(primary):
    # Ubuntu 26.04 with sudo-rs active: package sudo installs cvtsudoers as cvtsudoers.ws.
    if os.path.lexists(primary):
        return primary
    fallback = primary + ".ws"
    try:
        st = os.stat(fallback)
    except FileNotFoundError:
        return primary
    except Exception:
        error("cvtsudoers:fallback-stat-failed")
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
        error("cvtsudoers:untrusted-fallback")
    return fallback


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def map_target(logical):
    return fsroot / logical.lstrip("/")


def stable_regular_bytes(path, domain):
    try:
        first = os.lstat(path)
    except Exception:
        error(domain + ":lstat-failed")
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error(domain + ":invalid-type")
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error(domain + ":read-failed")
    if obj_state(first) != obj_state(second):
        error(domain + ":changed-during-check")
    return obj_state(first), raw


def policy_snapshot():
    # The sudoers pathset is the closure that visudo reports after validating the
    # active tree; no reviewed-policy file is read.  Identities and bytes of that
    # pathset are part of the snapshot, and the whole snapshot is compared
    # between the two policy observations of one check.
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, check=False)
    except Exception:
        error("visudo:execution-failed")
    if proc.returncode != 0:
        error("visudo:validation-failed")
    if not proc.stdout:
        error("visudo:invalid-output")
    if b"\x00" in proc.stdout or b"\r" in proc.stdout:
        error("visudo:invalid-bytes")
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("visudo:invalid-bytes")
    closure = []
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error("visudo:invalid-output")
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in closure:
            error("visudo:invalid-output")
        closure.append(path_text)
    if not closure or str(sudoers_path) not in closure:
        error("visudo:invalid-output")
    observed = {}
    escaped = False
    for path_text in sorted(closure):
        state, raw = stable_regular_bytes(Path(path_text), "sudoers")
        observed[path_text] = (state, hashlib.sha256(raw).hexdigest())
        escaped = escaped or ESCAPED_WHITESPACE.search(raw) is not None
    return tuple(sorted(observed.items())), escaped


def cvt_snapshot():
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run(
            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,
        )
    except Exception:
        error("cvtsudoers:execution-failed")
    if proc.returncode != 0 or proc.stderr:
        error("cvtsudoers:execution-failed")
    if not proc.stdout:
        error("cvtsudoers:invalid-output")
    if b"\x00" in proc.stdout:
        error("cvtsudoers:invalid-bytes")
    try:
        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))
    except Exception:
        error("cvtsudoers:invalid-output")
    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:
        error("cvtsudoers:invalid-output")
    defaults = data.get("Defaults", [])
    specs = data.get("User_Specs", [])
    if not isinstance(defaults, list) or not isinstance(specs, list):
        error("cvtsudoers:invalid-output")
    return proc.stdout, defaults, specs


def reject_enabled_runchroot_options(options):
    if options is None:
        return
    if not isinstance(options, list):
        error("sudo-policy:invalid-options")
    for obj in options:
        if not isinstance(obj, dict):
            error("sudo-policy:invalid-options")
        if "runchroot" in obj:
            if set(obj) != {"runchroot"}:
                error("sudo-policy:runchroot-mixed-option")
            if obj["runchroot"] is False:
                continue
            error("sudo-policy:runchroot-enabled")


def validate_defaults_shape(defaults):
    # Shape validation never depends on admission: an unmodelled Defaults document
    # means the policy was not observed completely, and an incompletely observed
    # policy cannot yield the determinate NOT_APPLICABLE result.
    if not isinstance(defaults, list):
        error("sudo-policy:invalid-defaults")
    for entry in defaults:
        if not isinstance(entry, dict) or set(entry) - {"Binding", "Options"} or "Options" not in entry:
            error("sudo-policy:invalid-defaults")
        binding = entry.get("Binding")
        if binding is not None and (not isinstance(binding, list) or not binding):
            error("sudo-policy:invalid-default-binding")
        options = entry["Options"]
        if not isinstance(options, list):
            error("sudo-policy:invalid-options")
        for obj in options:
            if not isinstance(obj, dict):
                error("sudo-policy:invalid-options")
            if "runchroot" in obj and set(obj) != {"runchroot"}:
                error("sudo-policy:runchroot-mixed-option")


def validate_defaults_applicability(defaults):
    # Applicability is evaluated only when the population is non-empty: Defaults
    # that cannot affect an explicit non-root-only Runas_Spec are out of scope.
    for entry in defaults:
        options = entry["Options"]
        reject_enabled_runchroot_options(options)
        for obj in options:
            # runas_default changes the implicit Runas_Spec; this adapter does not
            # evaluate Defaults binding precedence, so applicability is ambiguous.
            if "runas_default" in obj:
                error("sudo-policy:runas-default-unsupported")
            if "case_insensitive_user" in obj:
                error("sudo-policy:case-insensitive-user-unsupported")


def one_selector(obj, allowed):
    if not isinstance(obj, dict) or set(obj) - (allowed | {"negated"}):
        error("sudo-policy:ambiguous-selector")
    keys = [k for k in obj if k != "negated"]
    if len(keys) != 1 or not isinstance(obj.get("negated", False), bool):
        error("sudo-policy:ambiguous-selector")
    return keys[0], obj[keys[0]], obj.get("negated", False)


def validate_user_list(user_list):
    # Invoker identity does not narrow the population: any invoker able to run the
    # rule is out of scope for SRC-0008.  Only structural validity is required.
    if not isinstance(user_list, list) or not user_list:
        error("sudo-policy:invalid-user-list")
    for obj in user_list:
        if not isinstance(obj, dict) or not obj:
            error("sudo-policy:invalid-user-list")


def host_scope_supported(host_list):
    if not isinstance(host_list, list) or not host_list:
        error("sudo-policy:invalid-host-list")
    if len(host_list) != 1:
        error("sudo-policy:ambiguous-host-selector")
    key, value, neg = one_selector(host_list[0], {"hostname", "networkaddr", "netgroup"})
    if neg or key != "hostname" or value != "ALL":
        error("sudo-policy:unsupported-host-selector")
    return True


def root_runas_possible(spec):
    groups = spec.get("runasgroups")
    if groups is not None:
        if not isinstance(groups, list):
            error("sudo-policy:invalid-runas-list")
        # A group part next to a user part, as in (ALL:ALL), only selects the
        # target group; admission is decided by the user part below.  A
        # group-only Runas_Spec runs the command as the invoking user, which the
        # user-part rules below do not model, so it stays fail-closed.
        if groups and "runasusers" not in spec:
            error("sudo-policy:unsupported-runas-group")
    if "runasusers" not in spec:
        return True
    runas = spec["runasusers"]
    if not isinstance(runas, list) or not runas:
        error("sudo-policy:invalid-runas-list")
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "runasalias", "usergid", "usergroup", "userid", "username"}
    root_possible = False
    for obj in runas:
        key, value, neg = one_selector(obj, allowed)
        if neg or key not in {"username", "userid"}:
            error("sudo-policy:unsupported-runas-selector")
        if key == "username":
            if not isinstance(value, str) or not value:
                error("sudo-policy:invalid-runas-selector")
            if value == "ALL" or value.casefold() == "root":
                root_possible = True
            continue
        text = str(value)
        if not text.isdigit():
            error("sudo-policy:invalid-runas-selector")
        if int(text, 10) == 0:
            root_possible = True
    return root_possible


def logical_target(command, escaped):
    if not isinstance(command, str) or not command or any(c in command for c in "\x00\r\n"):
        error("sudo-policy:invalid-command")
    # sudoedit does not name an executable target of this control; it is excluded
    # before any other command-form check.
    if command == "sudoedit" or command.startswith("sudoedit "):
        return None
    # ALL names no concrete executable file of this control; the rights of
    # system programs are checked by 2.3.8.  Only explicit absolute pathnames
    # enter the population.
    if command == "ALL":
        return None
    if command.startswith("^"):
        error("sudo-policy:regex-command")
    if not command.startswith("/"):
        error("sudo-policy:nonabsolute-command")
    if any(c in command for c in WILDCARD_CHARS):
        error("sudo-policy:wildcard-command")
    # cvtsudoers JSON merges pathname and arguments into one string and unescapes
    # escaped whitespace inside a pathname.  The pathname boundary is provable only
    # when no file of the active sudoers closure has a backslash before whitespace
    # and the string has no whitespace other than a space or a tab: then the part
    # before the first space or tab is the pathname and the rest are arguments.
    # The filesystem is never used as an oracle for that boundary.
    if any(ch.isspace() for ch in command):
        if escaped or any(ch.isspace() and ch not in " \t" for ch in command):
            error("sudo-policy:unprovable-command-path")
        command = COMMAND_SEPARATOR.split(command, 1)[0]
    if command.endswith("/"):
        error("sudo-policy:directory-command")
    parts = command.split("/")
    if any(part in {".", ".."} for part in parts) or "\\" in command:
        error("sudo-policy:nonabsolute-command")
    return command


def collect_targets(specs, escaped):
    targets = set()
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error("sudo-policy:invalid-user-spec")
        validate_user_list(user_spec["User_List"])
        host_list = user_spec["Host_List"]
        if not isinstance(host_list, list) or not host_list:
            error("sudo-policy:invalid-host-list")
        cmnd_specs = user_spec["Cmnd_Specs"]
        if not isinstance(cmnd_specs, list):
            error("sudo-policy:invalid-command-specs")
        # Admission by runas is decided first: a rule whose targets can only run as
        # explicit non-root accounts is outside SRC-0008 and must not be rejected
        # because of an unsupported host scope or command option.
        admitted = []
        for spec in cmnd_specs:
            if not isinstance(spec, dict) or "Commands" not in spec or set(spec) - {"Commands", "runasusers", "runasgroups", "Options"}:
                error("sudo-policy:invalid-command-spec")
            if root_runas_possible(spec):
                admitted.append(spec)
        if not admitted:
            continue
        host_scope_supported(host_list)
        for spec in admitted:
            options = spec.get("Options")
            reject_enabled_runchroot_options(options)
            if options is not None:
                if not isinstance(options, list):
                    error("sudo-policy:invalid-command-options")
                for obj in options:
                    if not isinstance(obj, dict):
                        error("sudo-policy:invalid-command-options")
                    if "notbefore" in obj or "notafter" in obj:
                        error("sudo-policy:time-qualified-command")
            commands = spec["Commands"]
            if not isinstance(commands, list) or not commands:
                error("sudo-policy:invalid-command-list")
            for obj in commands:
                if not isinstance(obj, dict) or set(obj) - ALLOWED_COMMAND_KEYS:
                    error("sudo-policy:invalid-command-entry")
                if "command" not in obj or not isinstance(obj.get("negated", False), bool):
                    error("sudo-policy:invalid-command-entry")
                if any(key in obj for key in ("sha224", "sha256", "sha384", "sha512")):
                    error("sudo-policy:digest-qualified-command")
                if obj.get("negated", False):
                    error("sudo-policy:negated-command")
                target = logical_target(obj["command"], escaped)
                if target is not None:
                    targets.add(target)
    return tuple(sorted(targets, key=os.fsencode))


def stable_target(logical):
    path = map_target(logical)
    try:
        link_first = os.lstat(path)
        target_first = os.stat(path, follow_symlinks=True)
        resolved = os.path.realpath(path)
        link_second = os.lstat(path)
        target_second = os.stat(path, follow_symlinks=True)
    except Exception:
        error("target:snapshot-failed")
    if obj_state(link_first) != obj_state(link_second) or obj_state(target_first) != obj_state(target_second):
        error("target:changed-during-check")
    if not stat.S_ISREG(target_first.st_mode) or (stat.S_IMODE(target_first.st_mode) & 0o111) == 0:
        error("target:invalid-type")
    if fsroot != Path("/"):
        try:
            Path(resolved).relative_to(fsroot.resolve())
        except Exception:
            error("target:outside-root")
    if target_first.st_nlink != 1:
        error("target:ambiguous-identity")
    return (logical, resolved, obj_state(link_first), obj_state(target_first))


def stable_optional_regular_bytes(path, domain):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        # Absence is a legitimate state for the two optional UID-range sources.
        # It is recorded so that the final owner-authority revalidation can detect
        # an absent->present transition.
        try:
            os.lstat(path)
        except FileNotFoundError:
            return ("ABSENT",), None
        except Exception:
            error(domain + ":stat-failed")
        error(domain + ":changed-during-check")
    except Exception:
        error(domain + ":stat-failed")
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error(domain + ":invalid-type")
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error(domain + ":read-failed")
    if obj_state(first) != obj_state(second):
        error(domain + ":changed-during-check")
    return ("PRESENT", obj_state(first), hashlib.sha256(raw).hexdigest()), raw


def read_uid_range(path, pattern, keys, domain):
    mapped = map_target(str(path))
    snapshot, raw = stable_optional_regular_bytes(mapped, domain)
    if raw is None:
        return None, snapshot
    if b"\x00" in raw:
        error(domain + ":invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error(domain + ":invalid-bytes")
    found = {}
    named = False
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        head = RANGE_KEY_HEAD.match(line)
        if head is not None and head.group(1).upper() in keys:
            named = True
        match = pattern.match(line)
        if match is None:
            continue
        name, value = match.group(1), match.group(2)
        if name not in keys:
            continue
        if name in found:
            error(domain + ":duplicate-key")
        found[name] = int(value, 10)
    # An existing source without any active line that names a key of the pair (for
    # example, adduser.conf of newer adduser versions with the defaults commented out)
    # gives no range and is treated like an absent source. A named key with a value that
    # does not match the range line, or one key of the pair without the other, makes the
    # source unusable, and an unusable source is an error rather than an absent one.
    if not found and not named:
        return None, snapshot
    if set(found) != set(keys):
        error(domain + ":incomplete-range")
    low, high = found[keys[0]], found[keys[1]]
    if low > high:
        error(domain + ":invalid-range")
    return (low, high), snapshot


def passwd_snapshot():
    mapped = map_target("/etc/passwd")
    state, raw = stable_regular_bytes(mapped, "passwd")
    if b"\x00" in raw or b"\r" in raw:
        error("passwd:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("passwd:invalid-bytes")
    by_uid = {}
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split(":")
        if len(fields) != 7:
            error("passwd:invalid-record")
        if not fields[2].isdigit():
            error("passwd:invalid-record")
        uid = int(fields[2], 10)
        by_uid.setdefault(uid, set()).add(fields[0])
    names = {uid: tuple(sorted(values)) for uid, values in by_uid.items()}
    snapshot = (state, hashlib.sha256(raw).hexdigest())
    return snapshot, names


def owner_sources():
    ranges = []
    tokens = []

    login, login_token = read_uid_range(
        login_defs_path, UID_RANGE_LINE, ("UID_MIN", "UID_MAX"), "login-defs")
    tokens.append(("login-defs", login_token))
    if login is not None:
        ranges.append(login)

    adduser, adduser_token = read_uid_range(
        adduser_conf_path, CONF_RANGE_LINE, ("FIRST_UID", "LAST_UID"), "adduser-conf")
    tokens.append(("adduser-conf", adduser_token))
    if adduser is not None:
        ranges.append(adduser)

    if not ranges:
        # Without any usable range source a non-root owner cannot be classified as
        # regular or non-regular, and a fallback default would invent authority.
        error("owner-classification:no-source")

    passwd_token, passwd_names = passwd_snapshot()
    tokens.append(("passwd", passwd_token))
    return tuple(ranges), passwd_names, tuple(tokens)


def owner_condition(uid, ranges, passwd_names):
    if uid == 0:
        return False
    names = passwd_names.get(uid, ())
    if not names:
        error("owner-classification:unknown-uid")
    if len(names) != 1:
        error("owner-classification:ambiguous-uid")
    verdicts = {low <= uid <= high for (low, high) in ranges}
    if len(verdicts) != 1:
        error("owner-classification:conflicting-sources")
    return verdicts.pop()


cvtsudoers_path = resolve_cvtsudoers(cvtsudoers_path)
policy_before = policy_snapshot()
cvt_before, defaults, specs = cvt_snapshot()

# Population admission is decided before semantic Defaults validation.  Defaults
# that cannot affect an explicit non-root-only Runas_Spec are outside SRC-0008 and
# must not turn a clean empty population into ERROR.  When at least one target is
# admitted, the current fail-closed Defaults boundary remains unchanged.
validate_defaults_shape(defaults)
targets = collect_targets(specs, policy_before[1])
if not targets:
    policy_after = policy_snapshot()
    cvt_after, defaults_after, specs_after = cvt_snapshot()
    validate_defaults_shape(defaults_after)
    if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after, policy_after[1]) != ():
        error("observation:policy-changed")
    print("NOT_APPLICABLE\tfiles=0;owner_violations=0;mode_violations=0\tNOT_APPLICABLE")
    raise SystemExit(0)

validate_defaults_applicability(defaults)
records = {logical: stable_target(logical) for logical in targets}

# UID 0 is decided without OWNER classification sources.  For any non-root owner,
# capture all OWNER-authority inputs once, classify only from that snapshot, then
# re-read and compare those inputs after the second policy/cvtsudoers snapshot.
owner_before = None
ranges = ()
passwd_names = {}
if any(rec[3][2] != 0 for rec in records.values()):
    ranges, passwd_names, owner_before = owner_sources()

owner_bad = 0
mode_bad = 0
for rec in records.values():
    state = rec[3]
    if owner_condition(state[2], ranges, passwd_names):
        owner_bad += 1
    if state[4] & 0o002:
        mode_bad += 1

policy_after = policy_snapshot()
cvt_after, defaults_after, specs_after = cvt_snapshot()
validate_defaults_shape(defaults_after)
validate_defaults_applicability(defaults_after)
if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after, policy_after[1]) != targets:
    error("observation:policy-changed")

if owner_before is not None:
    ranges_after, passwd_names_after, owner_after = owner_sources()
    if owner_after != owner_before:
        error("owner-authority:changed-during-check")

for logical, before in records.items():
    if stable_target(logical) != before:
        error("observation:target-changed")

print("VALUE\tfiles=%d;owner_violations=%d;mode_violations=%d\t%s" % (
    len(targets), owner_bad, mode_bad, "PASS" if owner_bad == 0 and mode_bad == 0 else "FAIL"))

SLP_SUDO_ROOT_FILES_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:execution-failed\tERROR\n' "$_slp_cid"; return 0; fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "${_slp_obs#*$'\t'}"; return 0; fi
  if [[ $_slp_obs == NOT_APPLICABLE$'\t'* ]]; then IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"; if [[ -z "$_slp_value" || -n "$_slp_extra" || "$_slp_compliance" != NOT_APPLICABLE ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi; printf 'SLP-CHECK-V1\t%s\tNOT_APPLICABLE\t%s\tNOT_APPLICABLE\n' "$_slp_cid" "$_slp_value"; return 0; fi
  IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ "$_slp_kind" != VALUE || -z "$_slp_value" || -n "$_slp_extra" || ( "$_slp_compliance" != PASS && "$_slp_compliance" != FAIL ) ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\t%s\t%s\n' "$_slp_cid" "$_slp_value" "$_slp_compliance"
}

slp_check_FSTEC_LINUX_2022_2_3_5_STARTUP_FILES_WRITE_PROTECTION() {
  local _slp_obs _slp_status _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '["/etc/rc0.d","/etc/rc1.d","/etc/rc2.d","/etc/rc3.d","/etc/rc4.d","/etc/rc5.d","/etc/rc6.d"]' 'null' '/usr/bin/systemd-analyze' '0002' <<'SLP_STARTUP_FILES_PY'
import json, os, stat, subprocess, sys

rc_roots = json.loads(sys.argv[1])
unit_paths_override = json.loads(sys.argv[2])
systemd_analyze = sys.argv[3]
expected_mask = int(sys.argv[4], 8)


def emit_error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def state_lstat(path):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def state_stat(path):
    st = os.stat(path, follow_symlinks=True)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def root_exists(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        emit_error("root:stat-failed")
    return True


def dir_identity(path):
    st = os.stat(path, follow_symlinks=True)
    if not stat.S_ISDIR(st.st_mode):
        emit_error("directory:invalid-type")
    return (st.st_dev, st.st_ino)


def direct_names(root):
    try:
        names = []
        with os.scandir(root) as it:
            for ent in it:
                names.append(ent.name)
        names.sort(key=os.fsencode)
        return tuple(names)
    except Exception:
        emit_error("directory:scan-failed")


def direct_service_names(root):
    return tuple(x for x in direct_names(root) if x.endswith(".service"))


def resolve_candidate(path, service_role):
    try:
        first_l = state_lstat(path)
    except Exception:
        emit_error("target:lstat-failed")
    mode_type = first_l[4]
    if stat.S_ISDIR(mode_type):
        if service_role:
            emit_error("target:invalid-type")
        return ("directory", None, first_l, None)
    if stat.S_ISLNK(mode_type):
        try:
            target = os.path.realpath(path)
        except Exception:
            emit_error("target:resolve-failed")
        if service_role and os.path.normpath(target) == "/dev/null":
            try:
                if state_lstat(path) != first_l:
                    emit_error("target:changed-during-check")
            except Exception:
                emit_error("target:lstat-failed")
            resolution_snapshots[path] = target
            return ("masked", None, first_l, None)
        try:
            target_state = state_stat(target)
        except FileNotFoundError:
            # Битая ссылка: цели нет (решение пользователя 07.10.2026).
            emit_error("target:dangling-link")
        except Exception:
            emit_error("target:stat-failed")
        if not stat.S_ISREG(target_state[4]):
            emit_error("target:invalid-type")
        resolution_snapshots[path] = target
        return ("regular", target, first_l, target_state)
    if stat.S_ISREG(mode_type):
        try:
            target_state = state_stat(path)
        except Exception:
            emit_error("target:stat-failed")
        return ("regular", path, first_l, target_state)
    emit_error("target:invalid-type")


def read_unit_paths():
    if unit_paths_override is not None:
        if not isinstance(unit_paths_override, list) or any(not isinstance(x, str) for x in unit_paths_override):
            emit_error("systemd:invalid-unit-paths")
        return tuple(unit_paths_override), None
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([systemd_analyze, "unit-paths"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    except Exception:
        emit_error("systemd:execution-failed")
    if proc.returncode != 0:
        emit_error("systemd:execution-failed")
    if proc.stderr:
        emit_error("systemd:stderr-output")
    if not proc.stdout:
        emit_error("systemd:empty-output")
    if b"\x00" in proc.stdout or b"\r" in proc.stdout:
        emit_error("systemd:invalid-bytes")
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        emit_error("systemd:invalid-utf8")
    paths = []
    for line in text.splitlines():
        if not line.startswith("/") or "\x00" in line or "\r" in line or "\n" in line:
            emit_error("systemd:invalid-path")
        paths.append(line)
    if not paths:
        emit_error("systemd:empty-population")
    return tuple(paths), proc.stdout


unit_paths, unit_paths_raw = read_unit_paths()
initial_unit_paths = unit_paths
root_snapshots = {}
pop_snapshots = {}
entry_snapshots = {}
target_snapshots = {}
resolution_snapshots = {}
seen_root_ids = set()
seen_target_ids = set()

rc_roots_present = 0
rc_roots_absent = 0
rc_entries = 0
rc_directories = 0
rc_targets = 0
service_roots_present = 0
service_roots_absent = 0
service_root_aliases = 0
service_entries = 0
service_masked = 0
service_targets = 0
checked = 0
violations = 0


def remember_root_state(logical, resolved):
    try:
        exists = root_exists(logical); root_snapshots[logical] = (exists, state_lstat(logical) if exists else None, resolved, state_stat(resolved))
    except Exception:
        emit_error("root:snapshot-failed")


def remember_population(resolved, names, service_only):
    pop_snapshots[resolved] = (names, service_only)


def check_target(path, entry_path, entry_state, target_state, role):
    global checked, violations, rc_targets, service_targets
    ident = (target_state[0], target_state[1])
    if role == "rc":
        rc_targets += 1
    else:
        service_targets += 1
    entry_snapshots[entry_path] = entry_state
    target_snapshots[path] = target_state
    if ident in seen_target_ids:
        return
    seen_target_ids.add(ident)
    checked += 1
    if target_state[5] & expected_mask:
        violations += 1


# /etc/rc0.d ... /etc/rc6.d: direct file-like entries only; rcS.d is intentionally not in this population.
for logical in rc_roots:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error("root:invalid-path")
    exists = root_exists(logical)
    if not exists:
        rc_roots_absent += 1
        root_snapshots[logical] = (False, None, None, None)
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error("root:resolve-failed")
    rc_roots_present += 1
    names = direct_names(resolved)
    remember_root_state(logical, resolved)
    remember_population(resolved, names, False)
    # rc roots are fixed distinct runlevel directories; aliasing two roots would make the source population ambiguous.
    if ident in seen_root_ids:
        emit_error("root:ambiguous-alias")
    seen_root_ids.add(ident)
    for name in names:
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, False)
        if kind == "directory":
            rc_directories += 1
            continue
        rc_entries += 1
        check_target(target, path, entry_state, target_state, "rc")

# systemd unit load paths: scan only direct *.service entries. Dependency directories are references, not extra unit-file population.
for logical in unit_paths:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error("systemd:invalid-path")
    if not root_exists(logical):
        service_roots_absent += 1
        root_snapshots.setdefault(logical, (False, None, None, None))
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error("root:resolve-failed")
    service_roots_present += 1
    remember_root_state(logical, resolved)
    if ident in seen_root_ids:
        service_root_aliases += 1
        continue
    seen_root_ids.add(ident)
    names = direct_service_names(resolved)
    remember_population(resolved, names, True)
    for name in names:
        service_entries += 1
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, True)
        if kind == "masked":
            service_masked += 1
            entry_snapshots[path] = entry_state
            continue
        check_target(target, path, entry_state, target_state, "service")

# A fully observed empty .service population is vacuously compliant; discovery failures above are ERROR.

# End-of-observation stability: unit-path authority, roots, direct populations, entries and final targets must be unchanged.
if unit_paths_override is None:
    final_paths, final_raw = read_unit_paths()
    if final_paths != initial_unit_paths or final_raw != unit_paths_raw:
        emit_error("observation:unit-paths-changed")

for logical, snap in root_snapshots.items():
    was_present, logical_state, resolved, resolved_state = snap
    if not was_present:
        if root_exists(logical):
            emit_error("observation:root-changed")
        continue
    try:
        if not root_exists(logical) or state_lstat(logical) != logical_state or os.path.realpath(logical) != resolved or state_stat(resolved) != resolved_state:
            emit_error("observation:root-changed")
    except Exception:
        emit_error("observation:root-unreadable")

for resolved, snap in pop_snapshots.items():
    names, service_only = snap
    current = direct_service_names(resolved) if service_only else direct_names(resolved)
    if current != names:
        emit_error("observation:population-changed")

for path, snap in entry_snapshots.items():
    try:
        if state_lstat(path) != snap:
            emit_error("observation:entry-changed")
    except Exception:
        emit_error("observation:entry-unreadable")
for path, resolved in resolution_snapshots.items():
    try:
        if os.path.realpath(path) != resolved:
            emit_error("observation:resolution-changed")
    except Exception:
        emit_error("observation:resolution-failed")
for path, snap in target_snapshots.items():
    try:
        if state_stat(path) != snap:
            emit_error("observation:target-changed")
    except Exception:
        emit_error("observation:target-unreadable")

value = (
    f"rc_roots_present={rc_roots_present};rc_roots_absent={rc_roots_absent};rc_entries={rc_entries};"
    f"rc_directories={rc_directories};rc_targets={rc_targets};service_roots_present={service_roots_present};"
    f"service_roots_absent={service_roots_absent};service_root_aliases={service_root_aliases};"
    f"service_entries={service_entries};service_masked={service_masked};service_targets={service_targets};"
    f"checked={checked};violations={violations}"
)
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))

SLP_STARTUP_FILES_PY
  ) || { printf "%s\t%s\tERROR\tobserver:execution-failed\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION'; return 0; }
  if [[ $_slp_obs == ERROR$'	'* ]]; then
    printf "%s\t%s\tERROR\t%s\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' "${_slp_obs#*$'\t'}"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<<"$_slp_obs"
  if [[ $_slp_status != VALUE || -n $_slp_extra || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) ]]; then
    printf "%s\t%s\tERROR\tobserver:invalid-output\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION'
    return 0
  fi
  printf "%s\t%s\tVALUE\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D() {
  local _slp_path='/etc/cron.d'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY() {
  local _slp_path='/etc/cron.daily'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY() {
  local _slp_path='/etc/cron.hourly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY() {
  local _slp_path='/etc/cron.monthly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY() {
  local _slp_path='/etc/cron.weekly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB() {
  local _slp_path='/etc/crontab'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker _slp_stat_out
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_path" 2>&1 >/dev/null)
    if [[ -L "$_slp_path" || -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:state-changed" "ERROR"
    elif [[ $_slp_stat_out == *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:stat-failed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE() {
  local _slp_expected='0022' _slp_root _slp_probe _slp_entry _slp_mode _slp_scan_marker _slp_stat_out
  local _slp_find_rc _slp_sort_rc _slp_i
  local _slp_roots_present=0 _slp_roots_absent=0 _slp_checked=0 _slp_violations=0
  local -a _slp_roots=('/var/spool/cron/crontabs') _slp_entries=()
  local -A _slp_seen=()
  for _slp_root in "${_slp_roots[@]}"; do
    if [[ -L "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:symlink" "ERROR"
      return 0
    fi
    if [[ ! -e "$_slp_root" ]]; then
      _slp_probe=$_slp_root
      while [[ $_slp_probe != / && ! -e "$_slp_probe" && ! -L "$_slp_probe" ]]; do
        _slp_probe=${_slp_probe%/*}
        [[ -n $_slp_probe ]] || _slp_probe=/
      done
      if [[ -L "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-symlink" "ERROR"
        return 0
      fi
      if [[ ! -d "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-invalid-type" "ERROR"
        return 0
      fi
      if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-unsearchable" "ERROR"
        return 0
      fi
      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -- "$_slp_root" 2>&1 >/dev/null)
      if [[ -e "$_slp_root" || -L "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:state-changed" "ERROR"
        return 0
      fi
      if [[ $_slp_stat_out != *": No such file or directory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:stat-failed" "ERROR"
        return 0
      fi
      ((_slp_roots_absent+=1))
      continue
    fi
    if [[ ! -d "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:invalid-type" "ERROR"
      return 0
    fi
    ((_slp_roots_present+=1))
    _slp_entries=()
    mapfile -d '' -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_root" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
    )
    if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:missing-marker" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_scan_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:invalid-marker" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:find-failed" "ERROR"
      return 0
    fi
    if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:sort-failed" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi
      _slp_seen["$_slp_entry"]=1
      if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:symlink" "ERROR"
        return 0
      fi
      if [[ -d "$_slp_entry" ]]; then continue; fi
      if [[ ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:invalid-type" "ERROR"
        return 0
      fi
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:mode-read-failed" "ERROR"
        return 0
      fi
      if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:invalid-mode" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done
  local _slp_value="roots_present=$_slp_roots_present;roots_absent=$_slp_roots_absent;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE() {
  local _slp_expected='0022' _slp_role _slp_root _slp_resolved _slp_root_id
  local _slp_entry _slp_name _slp_candidate _slp_mode _slp_ident _slp_target _slp_scan_marker
  local _slp_find_rc _slp_sort_rc _slp_i _slp_uname_r='' _slp_path_env='' _slp_path_part
  local _slp_roots_present=0 _slp_roots_absent=0 _slp_aliases=0
  local _slp_exec=0 _slp_libraries=0 _slp_modules=0 _slp_checked=0 _slp_violations=0
  local -a _slp_exec_roots=('/bin' '/sbin' '/usr/bin' '/usr/sbin') _slp_lib_roots=('/lib' '/lib64' '/usr/lib' '/usr/lib64' '/usr/local/lib' '/usr/local/lib64') _slp_entries=() _slp_path_roots=()
  local _slp_module_root='/lib/modules/<uname-r>'
  local -A _slp_seen_roots=() _slp_seen_targets=()
  if (( EUID != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "runtime:requires-root" "ERROR"
    return 0
  fi
  _slp_path_env=${PATH-}
  if [[ -z "$_slp_path_env" || "$_slp_path_env" == *$'\r'* || "$_slp_path_env" == *$'\n'* || "$_slp_path_env" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:invalid-environment" "ERROR"
    return 0
  fi
  [[ "$_slp_path_env" != *: ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:nonabsolute-entry" "ERROR"; return 0; }
  IFS=: read -r -a _slp_path_roots <<< "$_slp_path_env"
  (( ${#_slp_path_roots[@]} > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:empty-environment" "ERROR"; return 0; }
  for _slp_path_part in "${_slp_path_roots[@]}"; do
    [[ "$_slp_path_part" == /* ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:nonabsolute-entry" "ERROR"; return 0; }
    _slp_exec_roots+=("$_slp_path_part")
  done
  if ! _slp_uname_r=$(command /usr/bin/uname -r 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "kernel:release-query-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_uname_r || $_slp_uname_r == *$'\n'* || $_slp_uname_r == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "kernel:invalid-release" "ERROR"
    return 0
  fi
  _slp_module_root=${_slp_module_root/<uname-r>/$_slp_uname_r}
  if [[ ! -x /usr/bin/python3 ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "runtime:python3-missing" "ERROR"
    return 0
  fi
  local _slp_observed=''
  if ! _slp_observed=$(LC_ALL=C command /usr/bin/python3 -I -S -B - 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "$_slp_expected" "${#_slp_exec_roots[@]}" "${#_slp_lib_roots[@]}" "${_slp_exec_roots[@]}" "${_slp_lib_roots[@]}" "$_slp_module_root" 2>/dev/null <<'SLP_SRC0012_PY'
import os
import stat
import subprocess
import sys

class ObservationError(Exception):
    pass

def error(reason):
    raise ObservationError(reason)

# readlink -f не завершается на ссылке вида l -> l/x (GNU coreutils 9.4): время ограничено.
READLINK_TIMEOUT = 5

def resolve(path, role):
    try:
        proc = subprocess.run([b"/usr/bin/readlink", b"-f", b"--", path],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=READLINK_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        error(role + ":resolve-failed")
    if proc.returncode != 0:
        error(role + ":resolve-failed")
    result = proc.stdout.rstrip(b"\n")
    if not result:
        error(role + ":resolve-empty")
    return result

def entries(root):
    try:
        proc = subprocess.run([b"/usr/bin/find", b"-P", b"--", root,
                               b"-mindepth", b"1", b"-print0"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        error("scan:find-failed")
    if proc.returncode != 0:
        error("scan:find-failed")
    if proc.stdout and not proc.stdout.endswith(b"\0"):
        error("scan:missing-marker")
    try:
        return sorted(proc.stdout.split(b"\0")[:-1]) if proc.stdout else []
    except MemoryError:
        error("scan:sort-failed")

def observe():
    mask = int(sys.argv[2], 8)
    ne, nl = int(sys.argv[3]), int(sys.argv[4])
    paths = [os.fsencode(p) for p in sys.argv[5:]]
    if len(paths) != ne + nl + 1:
        error("runtime:observer-arguments")
    groups = (("exec", paths[:ne]), ("lib", paths[ne:ne+nl]), ("module", paths[ne+nl:]))
    seen_roots, seen_targets = set(), set()
    exec_root_ids = set()
    for root in paths[:ne]:
        try:
            info = os.stat(root)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            exec_root_ids.add((info.st_dev, info.st_ino))
    present = absent = aliases = checked = violations = 0
    _slp_exec = _slp_libraries = _slp_modules = 0
    for role, roots in groups:
        for root in roots:
            try:
                os.lstat(root)
            except FileNotFoundError:
                absent += 1
                continue
            except OSError:
                error("root:resolve-failed")
            resolved = resolve(root, "root")
            if not os.path.isdir(resolved):
                error("root:invalid-type")
            try:
                info = os.stat(resolved)
            except OSError:
                error("root:identity-failed")
            present += 1
            identity = (info.st_dev, info.st_ino)
            if identity in seen_roots:
                aliases += 1
                continue
            seen_roots.add(identity)
            for entry in entries(resolved):
                if os.path.isdir(entry) and not os.path.islink(entry):
                    continue
                name = os.path.basename(entry)
                if role == "lib" and not (name.endswith(b".so") or b".so." in name or name.endswith(b".a")):
                    continue
                if role == "module" and not (name.endswith(b".ko") or b".ko." in name):
                    continue
                if os.path.islink(entry):
                    target = resolve(entry, "target")
                    if os.path.islink(target):
                        error("target:resolved-symlink")
                    if not os.path.isfile(target):
                        if role == "exec" and os.path.isdir(target):
                            try:
                                dinfo = os.stat(target)
                            except OSError:
                                error("target:identity-failed")
                            if (dinfo.st_dev, dinfo.st_ino) in exec_root_ids:
                                continue
                        error("target:invalid-type")
                elif os.path.isfile(entry):
                    target = entry
                else:
                    error("target:invalid-type")
                try:
                    info = os.stat(target)
                except OSError:
                    error("target:identity-failed")
                if not stat.S_ISREG(info.st_mode):
                    error("target:invalid-type")
                mode = stat.S_IMODE(info.st_mode)
                if len(format(mode, "o")) not in (3, 4):
                    error("target:invalid-mode")
                if role == "exec" and not mode & 0o111:
                    continue
                identity = (info.st_dev, info.st_ino)
                if identity in seen_targets:
                    continue
                seen_targets.add(identity)
                if role == "exec":
                    _slp_exec += 1
                elif role == "lib":
                    _slp_libraries += 1
                else:
                    _slp_modules += 1
                checked += 1
                if mode & mask:
                    violations += 1
    if _slp_exec == 0:
        error("population:missing-exec")
    if _slp_libraries == 0:
        error("population:missing-libraries")
    if _slp_modules == 0:
        error("population:missing-modules")
    value = (f"roots_present={present};roots_absent={absent};aliases={aliases};"
             f"exec={_slp_exec};libraries={_slp_libraries};modules={_slp_modules};"
             f"checked={checked};violations={violations}")
    return "VALUE", value, "FAIL" if violations else "PASS"

try:
    status, value, compliance = observe()
except ObservationError as exc:
    status, value, compliance = "ERROR", str(exc), "ERROR"
except Exception:
    status, value, compliance = "ERROR", "observer:execution-failed", "ERROR"
print("\t".join(("SLP-CHECK-V1", sys.argv[1], status, value, compliance)))
SLP_SRC0012_PY
  ); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  printf "%s\n" "$_slp_observed"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/proc/self/mountinfo' '0022' <<'SLP_SUID_SGID_PY'
import os, re, stat, sys

mountinfo_path, expected = sys.argv[1], sys.argv[2]

PSEUDO_FS = (
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
    "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "ramfs", "autofs",
    "binfmt_misc", "nsfs", "efivarfs",
)
SKIPPED_FS = ("fuse.portal",)
SELECT_BITS = 0o6000
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
_FORBIDDEN_PATH_CHARS = ("\r", "\n", "\t")


def _unescape_mountpoint(raw):
    return _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8) & 0xFF), raw)


def _under(path, top):
    return path != top and (top == "/" or path.startswith(top + "/"))


def _visible(mount, by_id, children):
    """True/False: видна ли точка монтирования по своему пути; None: неоднозначно.

    Скрыта, если поверх неё смонтирована другая (потомок с тем же путём), если другой потомок
    того же родителя смонтирован на тот же путь (неоднозначно) или на каталог выше по пути,
    либо если скрыт кто-то из родителей."""
    seen = set()
    below = None
    while True:
        mid, parent, mp = mount
        if mid in seen:
            return None
        seen.add(mid)
        for child in children.get(mid, ()):
            if child is not below and child[2] == mp:
                return False
        for other in children.get(parent, ()):
            if other is mount:
                continue
            if other[2] == mp:
                return None
            if _under(mp, other[2]):
                return False
        upper = by_id.get(parent)
        if upper is None or upper is mount:
            return True
        below, mount = mount, upper


def _scan_mount(mountpoint, skipped, found):
    try:
        root_dev = os.stat(mountpoint).st_dev
    except OSError:
        return "scan:find-failed"
    stack = [mountpoint]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            return "scan:find-failed"
        for entry in entries:
            if entry.path in skipped:
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                return "scan:find-failed"
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev == root_dev:
                    stack.append(entry.path)
            elif stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & SELECT_BITS:
                found.append((entry.path, st))
    return None


def _population(mountinfo_path):
    if os.path.islink(mountinfo_path):
        return "ERROR", "mountinfo:symlink"
    if not os.path.exists(mountinfo_path):
        return "ERROR", "mountinfo:not-found"
    if not os.path.isfile(mountinfo_path):
        return "ERROR", "mountinfo:invalid-type"
    if not os.access(mountinfo_path, os.R_OK):
        return "ERROR", "mountinfo:unreadable"
    try:
        with open(mountinfo_path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return "ERROR", "mountinfo:read-failed"
    if b"\x00" in raw:
        return "ERROR", "mountinfo:invalid-bytes"

    selected = []
    portals = []
    by_id = {}
    children = {}
    for line in raw.decode("utf-8", "surrogateescape").split("\n"):
        if not line:
            continue
        fields = line.split(" ", 6)
        if len(fields) != 7 or not all(fields):
            return "ERROR", "mountinfo:invalid-fields"
        if not (fields[0].isdigit() and fields[0].isascii() and fields[1].isdigit() and fields[1].isascii()):
            return "ERROR", "mountinfo:invalid-fields"
        tail = fields[6]
        if tail.startswith("- "):
            after = tail[2:]
        elif " - " in tail:
            after = tail.split(" - ", 1)[1]
        else:
            return "ERROR", "mountinfo:missing-separator"
        fstype = after.split(" ", 1)[0]
        if not fstype:
            return "ERROR", "mountinfo:missing-fstype"
        mount = (int(fields[0]), int(fields[1]), _unescape_mountpoint(fields[4]))
        if mount[0] in by_id:
            return "ERROR", "mountinfo:duplicate-id"
        by_id[mount[0]] = mount
        children.setdefault(mount[1], []).append(mount)
        if fstype in SKIPPED_FS:
            portals.append(mount)
        elif fstype not in PSEUDO_FS:
            selected.append(fields[4])

    # Цикл parent ID в любом месте дерева: ERROR до решений о видимости.
    for mount in by_id.values():
        chain = set()
        while True:
            if mount[0] in chain:
                return "ERROR", "mountinfo:ambiguous-visibility"
            chain.add(mount[0])
            upper = by_id.get(mount[1])
            if upper is None or upper is mount:
                break
            mount = upper

    skipped = set()
    for mount in portals:
        visible = _visible(mount, by_id, children)
        if visible is None:
            return "ERROR", "mountinfo:ambiguous-visibility"
        if visible:
            skipped.add(mount[2])

    seen_mounts = set()
    seen_files = set()
    items = []
    mounts = 0
    for raw_mountpoint in selected:
        mountpoint = _unescape_mountpoint(raw_mountpoint)
        if mountpoint in skipped:
            continue
        if not mountpoint.startswith("/") or any(c in mountpoint for c in _FORBIDDEN_PATH_CHARS):
            return "ERROR", "mountinfo:invalid-mountpoint"
        # Монтирование файла поверх файла (например, том subPath Kubernetes): не каталог, а один
        # обычный файл; в population входит сам этот файл (решение пользователя 14.10.2026).
        if os.path.isfile(mountpoint):
            try:
                file_st = os.stat(mountpoint)
            except OSError:
                return "ERROR", "mountinfo:identity-failed"
            if not stat.S_ISREG(file_st.st_mode):
                return "ERROR", "mountinfo:missing-mountpoint"
            identity = (file_st.st_dev, file_st.st_ino)
            if identity in seen_mounts:
                continue
            seen_mounts.add(identity)
            mounts += 1
            if stat.S_IMODE(file_st.st_mode) & SELECT_BITS and identity not in seen_files:
                seen_files.add(identity)
                items.append((mountpoint, file_st))
            continue
        if not os.path.isdir(mountpoint):
            return "ERROR", "mountinfo:missing-mountpoint"
        try:
            root_st = os.stat(mountpoint)
        except OSError:
            return "ERROR", "mountinfo:identity-failed"
        identity = (root_st.st_dev, root_st.st_ino)
        if identity in seen_mounts:
            continue
        seen_mounts.add(identity)
        mounts += 1

        found = []
        reason = _scan_mount(mountpoint, skipped, found)
        if reason is not None:
            return "ERROR", reason
        found.sort(key=lambda pair: os.fsencode(pair[0]))
        for path, st in found:
            if any(c in path for c in _FORBIDDEN_PATH_CHARS):
                return "ERROR", "target:invalid-path"
            file_identity = (st.st_dev, st.st_ino)
            if file_identity in seen_files:
                continue
            seen_files.add(file_identity)
            items.append((path, st))

    if mounts == 0:
        return "ERROR", "mountinfo:empty-population"
    return "VALUE", (mounts, items)


if re.fullmatch(r"[0-7]{3,4}", expected) is None:
    print("ERROR\tobserver:invalid-arguments")
    raise SystemExit(0)
mask = int(expected, 8)
status, data = _population(mountinfo_path)
if status == "ERROR":
    print("ERROR\t" + data)
else:
    mounts, items = data
    violations = sum(1 for _path, st in items if stat.S_IMODE(st.st_mode) & mask)
    print("VALUE\tmounts=%d;checked=%d;violations=%d\t%s"
          % (mounts, len(items), violations, "PASS" if violations == 0 else "FAIL"))
SLP_SUID_SGID_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE() {
  local _slp_home='/home'
  local _slp_expected='0077'
  local _slp_entry _slp_base _slp_mode
  local _slp_ident _slp_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_probe _slp_stat_out _slp_reason _slp_target _slp_bad
  local _slp_ctl=$'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f'
  local _slp_homes=0 _slp_checked=0 _slp_violations=0 _slp_dynamic=0
  local -a _slp_entries=() _slp_home_entries=()
  local -A _slp_seen_targets=() _slp_seen_entries=()

  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_home" 2>&1)
  if (( $? != 0 )); then
    if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
      printf -v _slp_reason 'home-base:stat-failed:%s' "$_slp_home"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    _slp_probe=$_slp_home
    while [[ $_slp_probe != / ]]; do
      _slp_probe=${_slp_probe%/*}
      [[ -n $_slp_probe ]] || _slp_probe=/
      if [[ $_slp_probe == / ]]; then break; fi
      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_probe" 2>&1)
      if (( $? == 0 )); then break; fi
      if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
        printf -v _slp_reason 'home-base:ancestor-stat-failed:%s' "$_slp_probe"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
        return 0
      fi
    done
    if [[ $_slp_probe == / ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "homes=0;discovered=0;checked=0;violations=0" "PASS"
      return 0
    fi
    case "$_slp_stat_out" in
      'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-symlink" "ERROR"
        return 0 ;;
      directory) ;;
      *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-invalid-type" "ERROR"
        return 0 ;;
    esac
    if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-unsearchable" "ERROR"
      return 0
    fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "homes=0;discovered=0;checked=0;violations=0" "PASS"
    return 0
  fi
  case "$_slp_stat_out" in
    'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:symlink" "ERROR"
      return 0 ;;
    directory) ;;
    *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:invalid-type" "ERROR"
      return 0 ;;
  esac

  _slp_home_entries=()
  mapfile -d "" -t _slp_home_entries < <(
    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
  )
  if (( ${#_slp_home_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_home_entries[@]}-1))
  _slp_marker=${_slp_home_entries[$_slp_i]}
  unset '_slp_home_entries[$_slp_i]'
  if [[ ! $_slp_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_home_entries[@]}"; do
    if [[ ${_slp_seen_entries["$_slp_entry"]+x} ]]; then continue; fi
    _slp_seen_entries["$_slp_entry"]=1
    _slp_bad=0
    if [[ "$_slp_entry" == *["$_slp_ctl"]* ]]; then _slp_bad=1; fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_entry" 2>&1)
    if (( $? != 0 )); then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      if [[ "$_slp_stat_out" == *": No such file or directory" ]]; then
        printf -v _slp_reason 'home:vanished:%s' "$_slp_entry"
      else
        printf -v _slp_reason 'home:stat-failed:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" == "symbolic link" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null && printf x)
      if [[ $? -eq 0 ]]; then
        _slp_target=${_slp_target%x}
        _slp_target=${_slp_target%$'\n'}
        if [[ "$_slp_target" == *["$_slp_ctl"]* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
          return 0
        elif [[ -n "$_slp_target" ]]; then
          printf -v _slp_reason 'home:symlink:%s->%s' "$_slp_entry" "$_slp_target"
        else
          printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
        fi
      else
        printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" != "directory" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      printf -v _slp_reason 'home:not-directory:%s' "$_slp_entry"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
      return 0
    fi
    _slp_home=$_slp_entry
    if [[ ! -r "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unreadable" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unsearchable" "ERROR"
      return 0
    fi
    ((_slp_homes+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -xdev -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
    )
    (( ${#_slp_entries[@]} > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:missing-marker" "ERROR"; return 0; }
    _slp_i=$((${#_slp_entries[@]}-1)); _slp_marker=${_slp_entries[$_slp_i]}; unset '_slp_entries[$_slp_i]'
    [[ "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:invalid-marker" "ERROR"; return 0; }
    _slp_find_rc=${BASH_REMATCH[1]}; _slp_sort_rc=${BASH_REMATCH[2]}
    (( _slp_find_rc == 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:find-failed" "ERROR"; return 0; }
    (( _slp_sort_rc == 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:sort-failed" "ERROR"; return 0; }
    for _slp_entry in "${_slp_entries[@]}"; do
      _slp_base=${_slp_entry##*/}
      case "$_slp_base" in
        .bash_history|.history|.sh_history|.bash_profile|.bashrc|.profile|.bash_logout|.rhosts|.bash_login|.xonshrc|.zsh_history|.zshrc|.zprofile|.zlogin|.zlogout|.zshenv|.ksh_history|.kshrc|.mkshrc|.cshrc|.tcshrc|.login|.logout) ;;
        *) continue ;;
      esac
      ((_slp_dynamic+=1))
      if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:symlink" "ERROR"
        return 0
      fi
      if [[ ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:invalid-type" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:identity-failed" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_targets["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:mode-read-failed" "ERROR"
        return 0
      fi
      [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:invalid-mode" "ERROR"; return 0; }
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done
  local _slp_value="homes=$_slp_homes;discovered=$_slp_dynamic;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_DIR_MODE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/etc/adduser.conf' <<'SLP_ADDUSER_CONF_PY'
import os, re, stat, sys

path = sys.argv[1]
NAMES_KEY = re.compile(r"[ \t\r\f\v]*DIR_MODE(?=[ \t\r\f\v=])", re.I)
CANONICAL = re.compile(r"DIR_MODE=([0-7]{3,4})")


def error(reason):
    print("ERROR\tadduser-conf:" + reason)
    raise SystemExit(0)


def ident(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    print("VALUE\tadduser-conf:absent\tFAIL")
    raise SystemExit(0)
except OSError as exc:
    if exc.errno == 40:
        error("invalid-type")
    error("read-failed")
try:
    first = os.fstat(fd)
    if not stat.S_ISREG(first.st_mode):
        error("invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    second = os.fstat(fd)
except OSError:
    error("read-failed")
finally:
    os.close(fd)
try:
    on_path = os.lstat(path)
except OSError:
    error("changed-during-check")
if ident(first) != ident(second) or (on_path.st_dev, on_path.st_ino) != (first.st_dev, first.st_ino):
    error("changed-during-check")
raw = b"".join(chunks)
if b"\x00" in raw:
    error("invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("invalid-bytes")
named = [line for line in text.split("\n")
         if line.strip() and not line.startswith("#") and NAMES_KEY.match(line)]
if not named:
    print("VALUE\tDIR_MODE:not-explicit\tFAIL")
    raise SystemExit(0)
if len(named) > 1:
    error("duplicate-key")
m = CANONICAL.fullmatch(named[0])
if m is None:
    error("noncanonical-line")
value = m.group(1)
if value in ("0700", "700"):
    print("VALUE\tDIR_MODE=0700\tPASS")
else:
    print("VALUE\tDIR_MODE=" + value + "\tFAIL")
SLP_ADDUSER_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE() {
  local _slp_home='/home' _slp_expected='0700'
  local _slp_probe _slp_entry _slp_mode _slp_scan_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_target _slp_reason _slp_bad _slp_stat_out
  local _slp_ctl=$'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f'
  local _slp_checked=0 _slp_violations=0
  local -a _slp_entries=()
  local -A _slp_seen=()
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_home" 2>&1)
  if (( $? != 0 )); then
    if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
      printf -v _slp_reason 'home-base:stat-failed:%s' "$_slp_home"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    _slp_probe=$_slp_home
    while [[ $_slp_probe != / ]]; do
      _slp_probe=${_slp_probe%/*}
      [[ -n $_slp_probe ]] || _slp_probe=/
      if [[ $_slp_probe == / ]]; then break; fi
      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_probe" 2>&1)
      if (( $? == 0 )); then break; fi
      if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
        printf -v _slp_reason 'home-base:ancestor-stat-failed:%s' "$_slp_probe"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
        return 0
      fi
    done
    if [[ $_slp_probe == / ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "checked=0;violations=0" "PASS"
      return 0
    fi
    case "$_slp_stat_out" in
      'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-symlink" "ERROR"
        return 0 ;;
      directory) ;;
      *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-invalid-type" "ERROR"
        return 0 ;;
    esac
    if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-unsearchable" "ERROR"
      return 0
    fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "checked=0;violations=0" "PASS"
    return 0
  fi
  case "$_slp_stat_out" in
    'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:symlink" "ERROR"
      return 0 ;;
    directory) ;;
    *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:invalid-type" "ERROR"
      return 0 ;;
  esac
  _slp_entries=()
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi
    _slp_seen["$_slp_entry"]=1
    _slp_bad=0
    if [[ "$_slp_entry" == *["$_slp_ctl"]* ]]; then _slp_bad=1; fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_entry" 2>&1)
    if (( $? != 0 )); then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      if [[ "$_slp_stat_out" == *": No such file or directory" ]]; then
        printf -v _slp_reason 'home:vanished:%s' "$_slp_entry"
      else
        printf -v _slp_reason 'home:stat-failed:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" == "symbolic link" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null && printf x)
      if [[ $? -eq 0 ]]; then
        _slp_target=${_slp_target%x}
        _slp_target=${_slp_target%$'\n'}
        if [[ "$_slp_target" == *["$_slp_ctl"]* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
          return 0
        elif [[ -n "$_slp_target" ]]; then
          printf -v _slp_reason 'home:symlink:%s->%s' "$_slp_entry" "$_slp_target"
        else
          printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
        fi
      else
        printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" != "directory" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      printf -v _slp_reason 'home:not-directory:%s' "$_slp_entry"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:mode-read-failed" "ERROR"
      return 0
    fi
    [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-mode" "ERROR"; return 0; }
    ((_slp_checked+=1))
    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi
  done
  local _slp_value="checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_HOME_MODE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'HOME_MODE' 'eq' '0700' '/etc/login.defs' <<'SLP_LOGIN_DEFS_PY'
import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с исходной сборкой (_active/current_value): разделители: только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии): ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_LOGIN_DEFS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT() {
  local _slp_path='/proc/sys/kernel/dmesg_restrict'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT() {
  local _slp_path='/proc/sys/kernel/kptr_restrict'
  local _slp_expected='2'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC() {
  local _slp_path='/proc/cmdline'
  local _slp_key='init_on_alloc'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE() {
  local _slp_path='/proc/cmdline'
  local _slp_key='slab_nomerge'
  local _slp_expected='true'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_values > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:unexpected-value-form" "ERROR"
    return 0
  fi
  if (( _slp_bare > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "VALUE" "true" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "VALUE" "false" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu'
  local _slp_expected='force'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu.passthrough'
  local _slp_expected='0'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu.strict'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET() {
  local _slp_path='/proc/cmdline'
  local _slp_key='randomize_kstack_offset'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS() {
  local _slp_path='/proc/cmdline'
  local _slp_key='mitigations'
  local _slp_expected='auto,nosmt'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN() {
  local _slp_path='/proc/sys/net/core/bpf_jit_harden'
  local _slp_expected='2'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL() {
  local _slp_path='/proc/cmdline'
  local _slp_key='vsyscall'
  local _slp_expected='none'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID() {
  local _slp_path='/proc/sys/kernel/perf_event_paranoid'
  local _slp_expected='3'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS() {
  local _slp_path='/proc/cmdline'
  local _slp_key='debugfs'
  local _slp_expected='off|no-mount'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  IFS='|' read -r -a _slp_choices <<< "$_slp_expected"
  for _slp_choice in "${_slp_choices[@]}"; do
    if [[ $_slp_first == "$_slp_choice" ]]; then
      _slp_comp=PASS
      break
    fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED() {
  local _slp_path='/proc/sys/kernel/kexec_load_disabled'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES() {
  local _slp_path='/proc/sys/user/max_user_namespaces'
  local _slp_expected='0'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED() {
  local _slp_path='/proc/sys/kernel/unprivileged_bpf_disabled'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD() {
  local _slp_path='/proc/sys/vm/unprivileged_userfaultfd'
  local _slp_expected='0'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD() {
  local _slp_path='/proc/sys/dev/tty/ldisc_autoload'
  local _slp_expected='0'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_9_TSX() {
  local _slp_path='/proc/cmdline'
  local _slp_key='tsx'
  local _slp_expected='off'
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR() {
  local _slp_path='/proc/sys/vm/mmap_min_addr'
  local _slp_expected='4096'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  if [[ $_slp_value == "$_slp_expected" ]]; then
    _slp_comp=PASS
  elif [[ $_slp_value == -* && $_slp_expected != -* ]]; then
    _slp_comp=FAIL
  elif [[ $_slp_value != -* && $_slp_expected == -* ]]; then
    _slp_comp=PASS
  else
    _slp_a=${_slp_value#-}
    _slp_b=${_slp_expected#-}
    _slp_negative=0
    [[ $_slp_value == -* ]] && _slp_negative=1
    if (( ${#_slp_a} != ${#_slp_b} )); then
      if (( _slp_negative == 0 )); then
        (( ${#_slp_a} > ${#_slp_b} )) && _slp_comp=PASS
      else
        (( ${#_slp_a} < ${#_slp_b} )) && _slp_comp=PASS
      fi
    else
      _slp_cmp=0
      _slp_i=0
      while (( _slp_i < ${#_slp_a} )); do
        _slp_ad=${_slp_a:_slp_i:1}
        _slp_bd=${_slp_b:_slp_i:1}
        if (( 10#$_slp_ad > 10#$_slp_bd )); then _slp_cmp=1; break; fi
        if (( 10#$_slp_ad < 10#$_slp_bd )); then _slp_cmp=-1; break; fi
        ((_slp_i+=1))
      done
      if (( _slp_negative == 0 )); then
        (( _slp_cmp >= 0 )) && _slp_comp=PASS
      else
        (( _slp_cmp <= 0 )) && _slp_comp=PASS
      fi
    fi
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE() {
  local _slp_path='/proc/sys/kernel/randomize_va_space'
  local _slp_expected='2'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE() {
  local _slp_path='/proc/sys/kernel/yama/ptrace_scope'
  local _slp_expected='3'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS() {
  local _slp_path='/proc/sys/fs/protected_symlinks'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS() {
  local _slp_path='/proc/sys/fs/protected_hardlinks'
  local _slp_expected='1'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS() {
  local _slp_path='/proc/sys/fs/protected_fifos'
  local _slp_expected='2'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR() {
  local _slp_path='/proc/sys/fs/protected_regular'
  local _slp_expected='2'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE() {
  local _slp_path='/proc/sys/fs/suid_dumpable'
  local _slp_expected='0'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_1_AUDITD_PACKAGE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'package' '/usr/bin/dpkg-query' '/usr/bin/systemctl' <<'SLP_AUDITD_PKG_PY'
import re, subprocess, sys

key, dpkg_query, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]

# Значения полей Status dpkg (want, eflag, status) и состояний systemd: закрытые перечни;
# иное значение: ERROR, а не несоответствие.
DPKG_WANT = ("unknown", "install", "hold", "deinstall", "purge")
DPKG_EFLAG = ("ok", "reinstreq")
DPKG_STATUS = ("not-installed", "config-files", "half-installed", "unpacked", "half-configured",
               "triggers-awaited", "triggers-pending", "installed")
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOAD_STATES = ("loaded", "not-found", "masked", "bad-setting", "error", "merged", "stub")
ACTIVE_STATES = ("active", "reloading", "inactive", "failed", "activating", "deactivating",
                 "maintenance", "refreshing")
UNIT_FILE_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked",
                    "masked-runtime", "static", "indirect", "disabled", "generated", "transient", "bad")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def package_state(rc, out):
    """(VALUE, соответствие) по коду возврата и stdout `dpkg-query -W -f=${Status}`."""
    if rc == 1 and not out:
        return "not-installed", False
    if rc != 0:
        raise ParseError("dpkg:query-failed")
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        raise ParseError("dpkg:invalid-output")
    parts = text.split(" ")
    if (len(parts) != 3 or parts[0] not in DPKG_WANT or parts[1] not in DPKG_EFLAG
            or parts[2] not in DPKG_STATUS):
        raise ParseError("dpkg:invalid-output")
    if text == "install ok installed":
        return "installed", True
    if text.endswith(" not-installed"):
        return "not-installed", False
    return text, False


def unit_props(rc, out):
    """(LoadState, ActiveState, UnitFileState) по выводу `systemctl show`."""
    if rc != 0:
        raise ParseError("systemd:query-failed")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            raise ParseError("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        raise ParseError("systemd:invalid-output")
    load, active, file_state = props["LoadState"], props["ActiveState"], props["UnitFileState"]
    if load not in LOAD_STATES or active not in ACTIVE_STATES:
        raise ParseError("systemd:invalid-output")
    # Пустой UnitFileState допустим только у юнита без файла (not-found).
    if file_state not in UNIT_FILE_STATES and not (file_state == "" and load == "not-found"):
        raise ParseError("systemd:invalid-output")
    return load, active, file_state


def service_state(load, active, file_state):
    """(VALUE, соответствие) службы по свойствам юнита."""
    if load == "not-found":
        return "not-found", False
    if load == "masked":
        return "masked/" + active, False
    if load != "loaded":
        raise ParseError("systemd:unit-load-" + load)
    return file_state + "/" + active, file_state == "enabled" and active == "active"


ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def call(argv, domain):
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=60, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        error(domain + ":query-failed")
    return res.returncode, res.stdout


try:
    if key == "package":
        rc, out = call([dpkg_query, "-W", "-f=${Status}", "auditd"], "dpkg")
        value, ok = package_state(rc, out)
    else:
        rc, out = call([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", "auditd.service"],
                       "systemd")
        value, ok = service_state(*unit_props(rc, out))
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_PKG_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_2_AUDITD_SERVICE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'service' '/usr/bin/dpkg-query' '/usr/bin/systemctl' <<'SLP_AUDITD_PKG_PY'
import re, subprocess, sys

key, dpkg_query, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]

# Значения полей Status dpkg (want, eflag, status) и состояний systemd: закрытые перечни;
# иное значение: ERROR, а не несоответствие.
DPKG_WANT = ("unknown", "install", "hold", "deinstall", "purge")
DPKG_EFLAG = ("ok", "reinstreq")
DPKG_STATUS = ("not-installed", "config-files", "half-installed", "unpacked", "half-configured",
               "triggers-awaited", "triggers-pending", "installed")
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOAD_STATES = ("loaded", "not-found", "masked", "bad-setting", "error", "merged", "stub")
ACTIVE_STATES = ("active", "reloading", "inactive", "failed", "activating", "deactivating",
                 "maintenance", "refreshing")
UNIT_FILE_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked",
                    "masked-runtime", "static", "indirect", "disabled", "generated", "transient", "bad")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def package_state(rc, out):
    """(VALUE, соответствие) по коду возврата и stdout `dpkg-query -W -f=${Status}`."""
    if rc == 1 and not out:
        return "not-installed", False
    if rc != 0:
        raise ParseError("dpkg:query-failed")
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        raise ParseError("dpkg:invalid-output")
    parts = text.split(" ")
    if (len(parts) != 3 or parts[0] not in DPKG_WANT or parts[1] not in DPKG_EFLAG
            or parts[2] not in DPKG_STATUS):
        raise ParseError("dpkg:invalid-output")
    if text == "install ok installed":
        return "installed", True
    if text.endswith(" not-installed"):
        return "not-installed", False
    return text, False


def unit_props(rc, out):
    """(LoadState, ActiveState, UnitFileState) по выводу `systemctl show`."""
    if rc != 0:
        raise ParseError("systemd:query-failed")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            raise ParseError("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        raise ParseError("systemd:invalid-output")
    load, active, file_state = props["LoadState"], props["ActiveState"], props["UnitFileState"]
    if load not in LOAD_STATES or active not in ACTIVE_STATES:
        raise ParseError("systemd:invalid-output")
    # Пустой UnitFileState допустим только у юнита без файла (not-found).
    if file_state not in UNIT_FILE_STATES and not (file_state == "" and load == "not-found"):
        raise ParseError("systemd:invalid-output")
    return load, active, file_state


def service_state(load, active, file_state):
    """(VALUE, соответствие) службы по свойствам юнита."""
    if load == "not-found":
        return "not-found", False
    if load == "masked":
        return "masked/" + active, False
    if load != "loaded":
        raise ParseError("systemd:unit-load-" + load)
    return file_state + "/" + active, file_state == "enabled" and active == "active"


ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def call(argv, domain):
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=60, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        error(domain + ":query-failed")
    return res.returncode, res.stdout


try:
    if key == "package":
        rc, out = call([dpkg_query, "-W", "-f=${Status}", "auditd"], "dpkg")
        value, ok = package_state(rc, out)
    else:
        rc, out = call([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", "auditd.service"],
                       "systemd")
        value, ok = service_state(*unit_props(rc, out))
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_PKG_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_ADMIN_SPACE_LEFT_ACTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'admin_space_left_action' 'word' 'suspend' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_DISK_FULL_ACTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'disk_full_action' 'word' 'suspend' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_FILE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'log_file' 'exact' '/var/log/audit/audit.log' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_FORMAT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'log_format' 'word' 'ENRICHED' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_GROUP() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'log_group' 'exact' 'root' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_MAX_LOG_FILE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'max_log_file' 'number' '50' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_MAX_LOG_FILE_ACTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'max_log_file_action' 'word' 'rotate' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_NUM_LOGS() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'num_logs' 'number' '150' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_SPACE_LEFT_ACTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'space_left_action' 'word' 'syslog' '/etc/audit/auditd.conf' <<'SLP_AUDITD_CONF_PY'
import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_AUDITD_CONF_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_4_AUDIT_RULES() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/etc/audit/rules.d' '/usr/sbin/auditctl' '' <<'SLP_AUDITD_RULES_PY'
import os, re, stat, subprocess, sys

rules_dir, auditctl, root_prefix = sys.argv[1], sys.argv[2], sys.argv[3]

# Набор правил таблицы 1 (SRC-0053) без примера myapp: (написание таблицы 1, вид в выводе
# `auditctl -l`). Нормализованный вид снят разведкой 01.10.2026 на средах 1–7 (одинаков побайтно).
RULES = (
    (b"-w /var/log -p w -k var_log_changes", b"-w /var/log -p w -k var_log_changes"),
    (b"-w /etc/group -p wa -k etcgroup", b"-w /etc/group -p wa -k etcgroup"),
    (b"-w /etc/passwd -p wa -k etcpasswd", b"-w /etc/passwd -p wa -k etcpasswd"),
    (b"-w /etc/gshadow -k etcgroup", b"-w /etc/gshadow -p rwxa -k etcgroup"),
    (b"-w /etc/shadow -k etcpasswd", b"-w /etc/shadow -p rwxa -k etcpasswd"),
    (b"-w /etc/security/opasswd -k opasswd", b"-w /etc/security/opasswd -p rwxa -k opasswd"),
    (b"-w /etc/adduser.conf -k adduserconf", b"-w /etc/adduser.conf -p rwxa -k adduserconf"),
    (b"-w /etc/sudoers -p wa -k actions", b"-w /etc/sudoers -p wa -k actions"),
    (b"-w /usr/bin/passwd -p x -k passwd_modification", b"-w /usr/bin/passwd -p x -k passwd_modification"),
    (b"-w /usr/bin/gpasswd -p x -k gpasswd_modification", b"-w /usr/bin/gpasswd -p x -k gpasswd_modification"),
    (b"-w /usr/sbin/groupadd -p x -k group_modification", b"-w /usr/sbin/groupadd -p x -k group_modification"),
    (b"-w /usr/sbin/groupmod -p x -k group_modification", b"-w /usr/sbin/groupmod -p x -k group_modification"),
    (b"-w /usr/sbin/addgroup -p x -k group_modification", b"-w /usr/sbin/addgroup -p x -k group_modification"),
    (b"-w /usr/sbin/useradd -p x -k user_modification", b"-w /usr/sbin/useradd -p x -k user_modification"),
    (b"-w /usr/sbin/usermod -p x -k user_modification", b"-w /usr/sbin/usermod -p x -k user_modification"),
    (b"-w /usr/sbin/adduser -p x -k user_modification", b"-w /usr/sbin/adduser -p x -k user_modification"),
    (b"-w /etc/login.defs -p wa -k login", b"-w /etc/login.defs -p wa -k login"),
    (b"-w /etc/securetty -p wa -k login", b"-w /etc/securetty -p wa -k login"),
    (b"-w /var/log/faillog -p wa -k login", b"-w /var/log/faillog -p wa -k login"),
    (b"-w /var/log/lastlog -p wa -k login", b"-w /var/log/lastlog -p wa -k login"),
    (b"-w /var/log/tallylog -p wa -k login", b"-w /var/log/tallylog -p wa -k login"),
    (b"-a exit,always -F arch=b64 -S execve -F uid=0 -k authentication_events",
     b"-a always,exit -F arch=b64 -S execve -F uid=0 -F key=authentication_events"),
    (b"-a exit,always -F arch=b32 -S execve -F uid=0 -k authentication_events",
     b"-a always,exit -F arch=b32 -S execve -F uid=0 -F key=authentication_events"),
    (b"-a exit,always -F arch=b64 -S bind -S connect -F success=0 -k network_events",
     b"-a always,exit -F arch=b64 -S connect,bind -F success=0 -F key=network_events"),
    (b"-w /dev/bus/usb -p rwxa -k usb", b"-w /dev/bus/usb -p rwxa -k usb"),
)


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def rule_file_names(names):
    """Имена загружаемых файлов правил: как `ls` без скрытых, имя оканчивается на .rules."""
    return sorted(n for n in names if not n.startswith(b".") and n.endswith(b".rules"))


def file_rule_lines(raw):
    """Множество строк файла правил без пробелов и табуляций по краям."""
    if b"\x00" in raw:
        raise ParseError("auditd-rules:invalid-bytes")
    return {line.strip(b" \t") for line in raw.split(b"\n")}


def present_in_files(lines):
    """Номера правил набора, записанных в файлах (в любом из двух написаний)."""
    return [i for i, (source, normal) in enumerate(RULES) if source in lines or normal in lines]


def present_in_kernel(output):
    """Номера правил набора в выводе `auditctl -l` (точная строка нормализованного вида)."""
    lines = set(output.split(b"\n"))
    return [i for i, (_source, normal) in enumerate(RULES) if normal in lines]


# Правило набора, которое пишется и требуется только при наличии каталога (решение пользователя
# 07.10.2026): без USB (например, ВМ Hyper-V) каталога /dev/bus/usb нет и auditctl отказывает в
# правиле наблюдения за ним, а вместе с ним не загружается весь набор.
CONDITIONAL = {b"-w /dev/bus/usb -p rwxa -k usb": "/dev/bus/usb"}


def applicable_rules(isdir):
    """Номера правил набора, применимых на этой машине; isdir(path): каталог есть."""
    return [i for i, (source, _normal) in enumerate(RULES)
            if source not in CONDITIONAL or isdir(CONDITIONAL[source])]


def shown_value(files, kernel, applicable):
    """Значение: files=<n>/<N> kernel=<m>/<N>; без каталога /dev/bus/usb: N=24 и usb=absent."""
    total = len(applicable)
    text = "files=%d/%d kernel=%d/%d" % (files, total, kernel, total)
    if total != len(RULES):
        text += " usb=absent"
    return text


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def trusted(st):
    return st.st_uid == 0 and not stat.S_IMODE(st.st_mode) & 0o022


try:
    dst = os.lstat(rules_dir)
except FileNotFoundError:
    print("VALUE\t<rules-dir-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-rules:stat-failed")
if not stat.S_ISDIR(dst.st_mode) or not trusted(dst):
    error("auditd-rules:dir-untrusted")
if not os.path.isfile(auditctl) or not os.access(auditctl, os.X_OK):
    print("VALUE\t<auditctl-absent>\tFAIL")
    raise SystemExit(0)
try:
    names = rule_file_names(os.listdir(os.fsencode(rules_dir)))
except OSError:
    error("auditd-rules:list-failed")
lines = set()
for name in names:
    path = os.path.join(os.fsencode(rules_dir), name)
    try:
        st = os.lstat(path)
    except OSError:
        error("auditd-rules:stat-failed")
    if not stat.S_ISREG(st.st_mode):
        error("auditd-rules:invalid-type")
    if not trusted(st):
        error("auditd-rules:untrusted")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error("auditd-rules:open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error("auditd-rules:read-failed")
    finally:
        os.close(fd)
    try:
        lines |= file_rule_lines(b"".join(chunks))
    except ParseError as exc:
        error(exc.reason)
try:
    res = subprocess.run([auditctl, "-l"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=60,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
except (OSError, subprocess.TimeoutExpired):
    error("auditd-rules:auditctl-failed")
if res.returncode != 0:
    error("auditd-rules:auditctl-failed")
applicable = set(applicable_rules(lambda path: os.path.isdir(root_prefix + path)))
files = len(set(present_in_files(lines)) & applicable)
kernel = len(set(present_in_kernel(res.stdout)) & applicable)
ok = files == len(applicable) and kernel == len(applicable)
print("VALUE\t%s\t%s" % (shown_value(files, kernel, applicable), "PASS" if ok else "FAIL"))
SLP_AUDITD_RULES_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LOGGING_2025_MAIN_5_AUDIT_LOG_FREE_SPACE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/var/log/audit' '7516192768' <<'SLP_AUDITD_SPACE_PY'
import os, sys

path, threshold = sys.argv[1], int(sys.argv[2])
while True:
    try:
        os.lstat(path)
        break
    except FileNotFoundError:
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    except OSError:
        print("ERROR\tauditd-log-space:stat-failed")
        raise SystemExit(0)
try:
    st = os.statvfs(path)
except OSError:
    print("ERROR\tauditd-log-space:statvfs-failed")
    raise SystemExit(0)
available = st.f_bavail * st.f_frsize
print("VALUE\t%d\t%s" % (available, "PASS" if available >= threshold else "FAIL"))
SLP_AUDITD_SPACE_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || ! $_slp_value =~ ^[0-9]+$ || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_ENCRYPT_METHOD() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'ENCRYPT_METHOD' 'one-of' 'SHA512|YESCRYPT' '/etc/login.defs' <<'SLP_LOGIN_DEFS_PY'
import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с исходной сборкой (_active/current_value): разделители: только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии): ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_LOGIN_DEFS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_EXISTING_PASSWORD_AGING() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra='' _slp_re='^accounts=[0-9]+;mismatched=[0-9]+$'
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'aging' '/etc/passwd' '/etc/shadow' 'root' <<'SLP_PW_AGING_PY'
import os, re, stat, sys, time

mode, passwd_path, shadow_path, owner_mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

# Разбор /etc/passwd и /etc/shadow: как у CHECK v2 2.1.1 (local-account-password-state), в том же
# порядке; популяция: записи с хэшем пароля (поле 2 /etc/shadow начинается с `$`).
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\$?")
NUMBER_RE = re.compile(r"[0-9]*")
AGING = ("1", "90", "7")  # поля 4–6: min, max, warn (политика компании, SRC-0055)
MAX_AGE = 90
NUM_DIGITS = 15  # больше значащих цифр: заведомо вне диапазона дат и сроков


def num(f):
    """Значение непустого поля из цифр. Значение длиннее NUM_DIGITS значащих цифр: бесконечность
    (больше любой даты и срока): int() для него не вызывается (лимит длины строки в int)."""
    s = f.lstrip("0")
    return float("inf") if len(s) > NUM_DIGITS else int(s or "0")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def file_problem(st, owner_ok):
    """Причина недоверия к файлу passwd/shadow по lstat или None."""
    if not stat.S_ISREG(st.st_mode):
        return "invalid-type"
    if st.st_nlink != 1:
        return "hardlinked"
    if not owner_ok(st.st_uid) or stat.S_IMODE(st.st_mode) & 0o022:
        return "untrusted"
    return None


def dir_problem(st, owner_ok):
    """Причина недоверия к каталогу файлов по lstat или None."""
    if not stat.S_ISDIR(st.st_mode):
        return "invalid-type"
    if not owner_ok(st.st_uid) or stat.S_IMODE(st.st_mode) & 0o022:
        return "untrusted"
    return None


def decode(raw, domain):
    """Байты как текст без потерь (latin-1): CHECK v2 2.1.1 не ограничивает кодировку полей,
    отвергает только NUL и CR."""
    if b"\x00" in raw or b"\r" in raw:
        raise ParseError(domain + ":invalid-bytes")
    return raw.decode("latin-1")


def records(text):
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def population(passwd_text, shadow_text):
    """[(имя, поля shadow)] записей с хэшем в порядке /etc/passwd; разбор: как CHECK v2 2.1.1."""
    passwd_lines = records(passwd_text)
    shadow_lines = records(shadow_text)
    if not passwd_lines:
        raise ParseError("passwd:empty-file")
    if not shadow_lines:
        raise ParseError("shadow:empty-file")
    shadow = {}
    for line in shadow_lines:
        if not line:
            raise ParseError("shadow:empty-record")
        parts = line.split(":")
        if len(parts) != 9:
            raise ParseError("shadow:invalid-fields")
        if NAME_RE.fullmatch(parts[0]) is None:
            raise ParseError("shadow:invalid-account")
        if parts[0] in shadow:
            raise ParseError("shadow:duplicate-account")
        shadow[parts[0]] = parts
    seen, out = set(), []
    for line in passwd_lines:
        if not line:
            raise ParseError("passwd:empty-record")
        parts = line.split(":")
        if len(parts) != 7:
            raise ParseError("passwd:invalid-fields")
        if NAME_RE.fullmatch(parts[0]) is None:
            raise ParseError("passwd:invalid-account")
        if parts[0] in seen:
            raise ParseError("passwd:duplicate-account")
        seen.add(parts[0])
        if parts[0] not in shadow:
            raise ParseError("passwd:missing-shadow-account")
        fields = shadow[parts[0]]
        if fields[1].startswith("$"):
            if any(NUMBER_RE.fullmatch(f) is None for f in fields[2:8]):
                raise ParseError("shadow:invalid-number")
            out.append((parts[0], fields))
    return out


def aging_ok(fields):
    """Поля 4–6 записи = 1/90/7 (по значению: пусто: несоответствие)."""
    return all(f != "" and num(f) == int(v) for f, v in zip(fields[3:6], AGING))


def age_state(fields, today):
    """None: возраст пароля соответствует политике; иначе счётчик контроля 2."""
    if fields[2] == "":
        return "date_empty"
    lastchg = num(fields[2])
    if lastchg == 0:
        return "date_zero"
    if lastchg > today:
        return "date_future"
    if today - lastchg > MAX_AGE:
        return "age_over"
    return None


def owner_ok(uid):
    return uid == 0 if owner_mode == "root" else uid == os.geteuid()


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read(path, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        error(domain + ":not-found")
    except OSError:
        error(domain + ":stat-failed")
    problem = file_problem(st, owner_ok)
    if problem is not None:
        error(domain + ":" + problem)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except PermissionError:
        error(domain + ":unreadable")
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


for directory in sorted({os.path.dirname(passwd_path), os.path.dirname(shadow_path)}):
    try:
        dst = os.lstat(directory)
    except OSError:
        error("etc:stat-failed")
    problem = dir_problem(dst, owner_ok)
    if problem is not None:
        error("etc:" + problem)
passwd_raw = read(passwd_path, "passwd")
shadow_raw = read(shadow_path, "shadow")
try:
    pop = population(decode(passwd_raw, "passwd"), decode(shadow_raw, "shadow"))
except ParseError as exc:
    error(exc.reason)
if mode == "aging":
    mismatched = sum(1 for _name, fields in pop if not aging_ok(fields))
    print("VALUE\taccounts=%d;mismatched=%d\t%s" % (len(pop), mismatched, "PASS" if mismatched == 0 else "FAIL"))
else:
    today = int(time.time()) // 86400
    counts = {"age_over": 0, "date_empty": 0, "date_zero": 0, "date_future": 0}
    for _name, fields in pop:
        state = age_state(fields, today)
        if state is not None:
            counts[state] += 1
    bad = sum(counts.values())
    print("VALUE\taccounts=%d;age_over=%d;date_empty=%d;date_zero=%d;date_future=%d\t%s" % (
        len(pop), counts["age_over"], counts["date_empty"], counts["date_zero"], counts["date_future"],
        "PASS" if bad == 0 else "FAIL"))
SLP_PW_AGING_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || ! $_slp_value =~ $_slp_re || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_MAX_DAYS() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'PASS_MAX_DAYS' 'eq' '90' '/etc/login.defs' <<'SLP_LOGIN_DEFS_PY'
import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с исходной сборкой (_active/current_value): разделители: только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии): ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_LOGIN_DEFS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_MIN_DAYS() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'PASS_MIN_DAYS' 'eq' '1' '/etc/login.defs' <<'SLP_LOGIN_DEFS_PY'
import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с исходной сборкой (_active/current_value): разделители: только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии): ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_LOGIN_DEFS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_WARN_AGE() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'PASS_WARN_AGE' 'eq' '7' '/etc/login.defs' <<'SLP_LOGIN_DEFS_PY'
import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с исходной сборкой (_active/current_value): разделители: только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии): ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
SLP_LOGIN_DEFS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_DCREDIT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'dcredit' 'eq' '-1' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_ENFORCE_FOR_ROOT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'enforce_for_root' 'eq' '1' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_LCREDIT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'lcredit' 'eq' '-1' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_MINLEN() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'minlen' 'ge' '12' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_OCREDIT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'ocredit' 'eq' '-1' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_RETRY() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'retry' 'eq' '3' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_UCREDIT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'ucredit' 'eq' '-1' '' <<'SLP_PWQUALITY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1, "enforcing": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата: ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def record_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value
    elif key == "enforce_for_root":
        # libpwquality set_name_value: настройка вида set включается при любом значении.
        settings[key] = True


def conf_settings(files):
    """Итог чтения конфигурации: files: [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            record_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


def root_enforcement(args, settings):
    """(enforce_for_root включён: 0/1, действующее enforcing). Флаг включается строкой конфигурации
    или аргументом модуля с любым значением (pwquality_set_option); enforcing: аргумент модуля →
    конфигурация → 1 (pam_pwquality отвергает пароль только при enforcing != 0)."""
    flag = bool(settings.get("enforce_for_root")) or any(
        a.partition(b"=")[0].lower() == b"enforce_for_root" for a in args)
    return (1 if flag else 0), effective("enforcing", args, settings)


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath): вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True: словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat: ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет: DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль); действующее enforcing = 0: FAIL, VALUE
    `<n>;enforcing=0` (для enforce_for_root: `enforce_for_root=<0|1>;enforcing=0`)."""
    flag, enforcing = root_enforcement(args, settings)
    if key == "enforce_for_root":
        value = 1 if flag and enforcing != 0 else 0
        shown = "enforce_for_root=%d;enforcing=%d" % (flag, enforcing)
    else:
        value = effective(key, args, settings)
        shown = str(value) if enforcing != 0 else "%d;enforcing=0" % value
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    # П.1.1: политика работает, если слабый пароль отклоняется; при enforcing = 0 pam_pwquality
    # только предупреждает: FAIL для каждого параметра (решение пользователя 08.10.2026).
    return shown, enforcing != 0 and compliant(op, expected, value)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
SLP_PWQUALITY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_2_PWHISTORY_ENFORCE_FOR_ROOT() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'enforce_for_root' 'eq' '1' '' <<'SLP_PWHISTORY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
REF_PWQ = (b"requisite", b"pam_pwquality.so", (b"retry=3",))
REF_HIST = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok"))
REF_HIST_ROOT = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok", b"enforce_for_root"))
REF_UNIX_CLEAN = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"yescrypt"))
REF_UNIX = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"use_authtok", b"try_first_pass", b"yescrypt"))
REF_TAIL = ((b"requisite", b"pam_deny.so", ()), (b"required", b"pam_permit.so", ()))
# Эталонные стеки password /etc/pam.d/common-password: подтверждены журналами семи сред
# (ВМ-прогон 27.09.2026, runner v21): чистая установка; стек, настроенный по п.1.1 (pam_pwquality);
# стек, настроенный по п.1.2 (профиль securelinux-pwhistory v1: "enabled", v2 с enforce_for_root:
# "enforced"). Иной стек: вне поддерживаемого состояния.
STACKS = {
    (REF_UNIX_CLEAN,) + REF_TAIL: "clean",
    (REF_PWQ, REF_UNIX) + REF_TAIL: "pwquality",
    (REF_PWQ, REF_HIST, REF_UNIX) + REF_TAIL: "enabled",
    (REF_PWQ, REF_HIST_ROOT, REF_UNIX) + REF_TAIL: "enforced",
}
REMEMBER = 5
CONF_PATHS = ("/etc/security/pwhistory.conf", "/usr/etc/security/pwhistory.conf")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def password_lines(raw):
    """[(тип, управление, модуль, аргументы)] действующих строк password файла PAM, по порядку."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    result = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        result.append((tokens[0], b" ".join(tokens[1:index + 1]), tokens[index + 1], tuple(tokens[index + 2:])))
    return result


def stack_state(raw):
    """"clean", "pwquality", "enabled" или "enforced": эталонный стек password; иной: ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    state = STACKS.get(tuple(line[1:] for line in lines))
    if state is None:
        raise ParseError("pam:unsupported-stack")
    return state


def semantic_state(raw):
    """Неэталонный стек password, разбор по смыслу (решение пользователя 07.10.2026):
    (remember, enforce_for_root) единственной строки pam_pwhistory, стоящей до единственной строки
    pam_unix, если её не может обойти предшествующая строка (только required/requisite);
    None: строки pam_pwhistory нет; иное: ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    names = [line[2].rsplit(b"/", 1)[-1] for line in lines]
    hist = [i for i, name in enumerate(names) if name == b"pam_pwhistory.so"]
    if not hist:
        return None
    unix = [i for i, name in enumerate(names) if name == b"pam_unix.so"]
    if len(hist) != 1 or len(unix) != 1 or hist[0] > unix[0]:
        raise ParseError("pam:pwhistory-position")
    if any(line[1] not in (b"required", b"requisite") for line in lines[:hist[0] + 1]):
        raise ParseError("pam:pwhistory-skippable")
    args = lines[hist[0]][3]
    remember = [arg[len(b"remember="):] for arg in args if arg.startswith(b"remember=")]
    if len(remember) != 1 or not remember[0].isdigit():
        raise ParseError("pam:pwhistory-remember")
    return int(remember[0]), 1 if b"enforce_for_root" in args else 0


def conf_active(raw):
    """True: в pwhistory.conf есть действующая строка (как pam_modutil_search_key: '#' отрезает
    комментарий, ведущие пробельные символы пропускаются, пустая строка не действует)."""
    for line in raw.split(b"\n"):
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        if line.lstrip(C_SPACE):
            return True
    return False


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, domain, missing_ok):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


pam_raw = read_regular(root + "/etc/pam.d/common-password", "pam", False)
semantic = None
try:
    state = stack_state(pam_raw)
except ParseError as exc:
    if exc.reason != "pam:unsupported-stack":
        error(exc.reason)
    try:
        semantic = semantic_state(pam_raw)
    except ParseError as sem_exc:
        error(sem_exc.reason)
    state = "manual" if semantic is not None else "foreign"
if state not in ("enabled", "enforced", "manual"):
    print("VALUE\t<module-absent>\tFAIL")
    raise SystemExit(0)
for conf in CONF_PATHS:
    raw = read_regular(root + conf, "pwhistory-conf", True)
    if raw is not None and conf_active(raw):
        error("pwhistory-conf:active-lines")
if semantic is not None:
    remember, enforced = semantic
else:
    remember, enforced = REMEMBER, (1 if state == "enforced" else 0)
if key == "enforce_for_root":
    print("VALUE\t" + str(enforced) + "\t" + ("PASS" if enforced == expected else "FAIL"))
else:
    print("VALUE\t" + str(remember) + "\t" + ("PASS" if remember >= expected else "FAIL"))
SLP_PWHISTORY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_1_2_PWHISTORY_REMEMBER() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'remember' 'ge' '5' '' <<'SLP_PWHISTORY_PY'
import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

C_SPACE = b" \t\n\v\f\r"
REF_PWQ = (b"requisite", b"pam_pwquality.so", (b"retry=3",))
REF_HIST = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok"))
REF_HIST_ROOT = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok", b"enforce_for_root"))
REF_UNIX_CLEAN = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"yescrypt"))
REF_UNIX = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"use_authtok", b"try_first_pass", b"yescrypt"))
REF_TAIL = ((b"requisite", b"pam_deny.so", ()), (b"required", b"pam_permit.so", ()))
# Эталонные стеки password /etc/pam.d/common-password: подтверждены журналами семи сред
# (ВМ-прогон 27.09.2026, runner v21): чистая установка; стек, настроенный по п.1.1 (pam_pwquality);
# стек, настроенный по п.1.2 (профиль securelinux-pwhistory v1: "enabled", v2 с enforce_for_root:
# "enforced"). Иной стек: вне поддерживаемого состояния.
STACKS = {
    (REF_UNIX_CLEAN,) + REF_TAIL: "clean",
    (REF_PWQ, REF_UNIX) + REF_TAIL: "pwquality",
    (REF_PWQ, REF_HIST, REF_UNIX) + REF_TAIL: "enabled",
    (REF_PWQ, REF_HIST_ROOT, REF_UNIX) + REF_TAIL: "enforced",
}
REMEMBER = 5
CONF_PATHS = ("/etc/security/pwhistory.conf", "/usr/etc/security/pwhistory.conf")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def password_lines(raw):
    """[(тип, управление, модуль, аргументы)] действующих строк password файла PAM, по порядку."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    result = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        result.append((tokens[0], b" ".join(tokens[1:index + 1]), tokens[index + 1], tuple(tokens[index + 2:])))
    return result


def stack_state(raw):
    """"clean", "pwquality", "enabled" или "enforced": эталонный стек password; иной: ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    state = STACKS.get(tuple(line[1:] for line in lines))
    if state is None:
        raise ParseError("pam:unsupported-stack")
    return state


def semantic_state(raw):
    """Неэталонный стек password, разбор по смыслу (решение пользователя 07.10.2026):
    (remember, enforce_for_root) единственной строки pam_pwhistory, стоящей до единственной строки
    pam_unix, если её не может обойти предшествующая строка (только required/requisite);
    None: строки pam_pwhistory нет; иное: ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    names = [line[2].rsplit(b"/", 1)[-1] for line in lines]
    hist = [i for i, name in enumerate(names) if name == b"pam_pwhistory.so"]
    if not hist:
        return None
    unix = [i for i, name in enumerate(names) if name == b"pam_unix.so"]
    if len(hist) != 1 or len(unix) != 1 or hist[0] > unix[0]:
        raise ParseError("pam:pwhistory-position")
    if any(line[1] not in (b"required", b"requisite") for line in lines[:hist[0] + 1]):
        raise ParseError("pam:pwhistory-skippable")
    args = lines[hist[0]][3]
    remember = [arg[len(b"remember="):] for arg in args if arg.startswith(b"remember=")]
    if len(remember) != 1 or not remember[0].isdigit():
        raise ParseError("pam:pwhistory-remember")
    return int(remember[0]), 1 if b"enforce_for_root" in args else 0


def conf_active(raw):
    """True: в pwhistory.conf есть действующая строка (как pam_modutil_search_key: '#' отрезает
    комментарий, ведущие пробельные символы пропускаются, пустая строка не действует)."""
    for line in raw.split(b"\n"):
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        if line.lstrip(C_SPACE):
            return True
    return False


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, domain, missing_ok):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


pam_raw = read_regular(root + "/etc/pam.d/common-password", "pam", False)
semantic = None
try:
    state = stack_state(pam_raw)
except ParseError as exc:
    if exc.reason != "pam:unsupported-stack":
        error(exc.reason)
    try:
        semantic = semantic_state(pam_raw)
    except ParseError as sem_exc:
        error(sem_exc.reason)
    state = "manual" if semantic is not None else "foreign"
if state not in ("enabled", "enforced", "manual"):
    print("VALUE\t<module-absent>\tFAIL")
    raise SystemExit(0)
for conf in CONF_PATHS:
    raw = read_regular(root + conf, "pwhistory-conf", True)
    if raw is not None and conf_active(raw):
        error("pwhistory-conf:active-lines")
if semantic is not None:
    remember, enforced = semantic
else:
    remember, enforced = REMEMBER, (1 if state == "enforced" else 0)
if key == "enforce_for_root":
    print("VALUE\t" + str(enforced) + "\t" + ("PASS" if enforced == expected else "FAIL"))
else:
    print("VALUE\t" + str(remember) + "\t" + ("PASS" if remember >= expected else "FAIL"))
SLP_PWHISTORY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_8_4_SSH_LOG_LEVEL() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == loglevel ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == loglevel ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == verbose ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != verbose ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^loglevel[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == verbose ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "VALUE" "main_global_verbose=$_slp_main_no;effective=verbose" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' "VALUE" "main_global_verbose=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PASSWORD_AUTHENTICATION() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == passwordauthentication ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == passwordauthentication ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^passwordauthentication[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_EMPTY_PASSWORDS() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == permitemptypasswords ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitemptypasswords ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitemptypasswords[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_ROOT_LOGIN() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == permitrootlogin ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitrootlogin ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_RECOMMENDED_CONFIGURATION_2026_9_1_SSH_KBD_INTERACTIVE_AUTHENTICATION() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == kbdinteractiveauthentication ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == kbdinteractiveauthentication ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- '/run/sshd' 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-runtime:privsep-dir-missing" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-config:validation-failed" "ERROR"
    fi
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^kbdinteractiveauthentication[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_11_2_FTP() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'ftp' '/proc' '/usr/bin/systemctl' <<'SLP_NETWORK_SERVICE_PY'
import re, subprocess, sys

key, proc_root, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]
SERVICES = {'ftp': (('vsftpd.service', 'proftpd.service', 'pure-ftpd.service'), (('tcp', 21),)), 'snmp': (('snmpd.service',), (('udp', 161),)), 'telnet': (('telnet.socket', 'telnetd.socket', 'telnetd.service', 'inetutils-telnetd.service'), (('tcp', 23),))}
ACTIVE_STATES = ('active', 'activating', 'reloading', 'refreshing', 'deactivating')
INACTIVE_STATES = ('inactive', 'failed', 'maintenance')
ENABLED_STATES = ('enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias', 'indirect')
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOCAL = re.compile(r"^[0-9A-F]+:([0-9A-F]{4})$")
STATE = re.compile(r"^[0-9A-F]{2}$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def listeners(proto, port):
    found = 0
    for suffix in ("", "6"):
        path = proc_root + "/net/" + proto + suffix
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            # Без IPv6 файла tcp6/udp6 нет; tcp/udp обязан быть.
            if suffix == "6":
                continue
            error("proc-net:read-failed")
        except OSError:
            error("proc-net:read-failed")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            error("proc-net:invalid-bytes")
        lines = text.split("\n")
        head = lines[0].split()
        # Обязательные поля заголовка: номер, локальный и удалённый адрес, состояние; у tcp6/udp6
        # удалённый адрес называется remote_address (ВМ-прогон 27.09.2026), у tcp/udp: rem_address.
        if head[:4] != ["sl", "local_address", "remote_address" if suffix == "6" else "rem_address", "st"]:
            error("proc-net:invalid-header")
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 10:
                error("proc-net:invalid-row")
            local, state = LOCAL.fullmatch(fields[1]), fields[3]
            if local is None or STATE.fullmatch(state) is None:
                error("proc-net:invalid-row")
            if int(local.group(1), 16) != port:
                continue
            # TCP: LISTEN (0A); UDP: привязанный сокет (07).
            if state == ("0A" if proto == "tcp" else "07"):
                found += 1
    return found


def unit_state(unit):
    try:
        res = subprocess.run([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        error("systemd:query-failed")
    if res.returncode != 0:
        error("systemd:query-failed")
    try:
        text = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        error("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            error("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        error("systemd:invalid-output")
    if props["ActiveState"] not in ACTIVE_STATES + INACTIVE_STATES:
        error("systemd:unit-state-unknown")
    return props["LoadState"], props["ActiveState"], props["UnitFileState"]


units, ports = SERVICES[key]
bad_units = []
for unit in units:
    load, active, file_state = unit_state(unit)
    if load in ("not-found", "masked"):
        # Юнит без файла или замаскированный: норма, только если не работает.
        if active in ACTIVE_STATES:
            bad_units.append(unit + ":" + active + "/" + (file_state or "-"))
        continue
    if load != "loaded":
        error("systemd:unit-load-" + (load if re.fullmatch(r"[a-z-]{1,32}", load) else "invalid"))
    if active in ACTIVE_STATES or file_state in ENABLED_STATES:
        bad_units.append(unit + ":" + (active or "-") + "/" + (file_state or "-"))
bad_ports = [str(port) + "/" + proto for proto, port in ports if listeners(proto, port)]
value = "units=" + (",".join(bad_units) or "-") + ";listeners=" + (",".join(bad_ports) or "-")
print("VALUE\t" + value + "\t" + ("FAIL" if bad_units or bad_ports else "PASS"))
SLP_NETWORK_SERVICE_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-FTP' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-FTP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-FTP' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-FTP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-FTP' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_11_2_SNMP() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'snmp' '/proc' '/usr/bin/systemctl' <<'SLP_NETWORK_SERVICE_PY'
import re, subprocess, sys

key, proc_root, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]
SERVICES = {'ftp': (('vsftpd.service', 'proftpd.service', 'pure-ftpd.service'), (('tcp', 21),)), 'snmp': (('snmpd.service',), (('udp', 161),)), 'telnet': (('telnet.socket', 'telnetd.socket', 'telnetd.service', 'inetutils-telnetd.service'), (('tcp', 23),))}
ACTIVE_STATES = ('active', 'activating', 'reloading', 'refreshing', 'deactivating')
INACTIVE_STATES = ('inactive', 'failed', 'maintenance')
ENABLED_STATES = ('enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias', 'indirect')
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOCAL = re.compile(r"^[0-9A-F]+:([0-9A-F]{4})$")
STATE = re.compile(r"^[0-9A-F]{2}$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def listeners(proto, port):
    found = 0
    for suffix in ("", "6"):
        path = proc_root + "/net/" + proto + suffix
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            # Без IPv6 файла tcp6/udp6 нет; tcp/udp обязан быть.
            if suffix == "6":
                continue
            error("proc-net:read-failed")
        except OSError:
            error("proc-net:read-failed")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            error("proc-net:invalid-bytes")
        lines = text.split("\n")
        head = lines[0].split()
        # Обязательные поля заголовка: номер, локальный и удалённый адрес, состояние; у tcp6/udp6
        # удалённый адрес называется remote_address (ВМ-прогон 27.09.2026), у tcp/udp: rem_address.
        if head[:4] != ["sl", "local_address", "remote_address" if suffix == "6" else "rem_address", "st"]:
            error("proc-net:invalid-header")
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 10:
                error("proc-net:invalid-row")
            local, state = LOCAL.fullmatch(fields[1]), fields[3]
            if local is None or STATE.fullmatch(state) is None:
                error("proc-net:invalid-row")
            if int(local.group(1), 16) != port:
                continue
            # TCP: LISTEN (0A); UDP: привязанный сокет (07).
            if state == ("0A" if proto == "tcp" else "07"):
                found += 1
    return found


def unit_state(unit):
    try:
        res = subprocess.run([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        error("systemd:query-failed")
    if res.returncode != 0:
        error("systemd:query-failed")
    try:
        text = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        error("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            error("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        error("systemd:invalid-output")
    if props["ActiveState"] not in ACTIVE_STATES + INACTIVE_STATES:
        error("systemd:unit-state-unknown")
    return props["LoadState"], props["ActiveState"], props["UnitFileState"]


units, ports = SERVICES[key]
bad_units = []
for unit in units:
    load, active, file_state = unit_state(unit)
    if load in ("not-found", "masked"):
        # Юнит без файла или замаскированный: норма, только если не работает.
        if active in ACTIVE_STATES:
            bad_units.append(unit + ":" + active + "/" + (file_state or "-"))
        continue
    if load != "loaded":
        error("systemd:unit-load-" + (load if re.fullmatch(r"[a-z-]{1,32}", load) else "invalid"))
    if active in ACTIVE_STATES or file_state in ENABLED_STATES:
        bad_units.append(unit + ":" + (active or "-") + "/" + (file_state or "-"))
bad_ports = [str(port) + "/" + proto for proto, port in ports if listeners(proto, port)]
value = "units=" + (",".join(bad_units) or "-") + ";listeners=" + (",".join(bad_ports) or "-")
print("VALUE\t" + value + "\t" + ("FAIL" if bad_units or bad_ports else "PASS"))
SLP_NETWORK_SERVICE_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_11_2_TELNET() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - 'telnet' '/proc' '/usr/bin/systemctl' <<'SLP_NETWORK_SERVICE_PY'
import re, subprocess, sys

key, proc_root, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]
SERVICES = {'ftp': (('vsftpd.service', 'proftpd.service', 'pure-ftpd.service'), (('tcp', 21),)), 'snmp': (('snmpd.service',), (('udp', 161),)), 'telnet': (('telnet.socket', 'telnetd.socket', 'telnetd.service', 'inetutils-telnetd.service'), (('tcp', 23),))}
ACTIVE_STATES = ('active', 'activating', 'reloading', 'refreshing', 'deactivating')
INACTIVE_STATES = ('inactive', 'failed', 'maintenance')
ENABLED_STATES = ('enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias', 'indirect')
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOCAL = re.compile(r"^[0-9A-F]+:([0-9A-F]{4})$")
STATE = re.compile(r"^[0-9A-F]{2}$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def listeners(proto, port):
    found = 0
    for suffix in ("", "6"):
        path = proc_root + "/net/" + proto + suffix
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            # Без IPv6 файла tcp6/udp6 нет; tcp/udp обязан быть.
            if suffix == "6":
                continue
            error("proc-net:read-failed")
        except OSError:
            error("proc-net:read-failed")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            error("proc-net:invalid-bytes")
        lines = text.split("\n")
        head = lines[0].split()
        # Обязательные поля заголовка: номер, локальный и удалённый адрес, состояние; у tcp6/udp6
        # удалённый адрес называется remote_address (ВМ-прогон 27.09.2026), у tcp/udp: rem_address.
        if head[:4] != ["sl", "local_address", "remote_address" if suffix == "6" else "rem_address", "st"]:
            error("proc-net:invalid-header")
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 10:
                error("proc-net:invalid-row")
            local, state = LOCAL.fullmatch(fields[1]), fields[3]
            if local is None or STATE.fullmatch(state) is None:
                error("proc-net:invalid-row")
            if int(local.group(1), 16) != port:
                continue
            # TCP: LISTEN (0A); UDP: привязанный сокет (07).
            if state == ("0A" if proto == "tcp" else "07"):
                found += 1
    return found


def unit_state(unit):
    try:
        res = subprocess.run([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        error("systemd:query-failed")
    if res.returncode != 0:
        error("systemd:query-failed")
    try:
        text = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        error("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            error("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        error("systemd:invalid-output")
    if props["ActiveState"] not in ACTIVE_STATES + INACTIVE_STATES:
        error("systemd:unit-state-unknown")
    return props["LoadState"], props["ActiveState"], props["UnitFileState"]


units, ports = SERVICES[key]
bad_units = []
for unit in units:
    load, active, file_state = unit_state(unit)
    if load in ("not-found", "masked"):
        # Юнит без файла или замаскированный: норма, только если не работает.
        if active in ACTIVE_STATES:
            bad_units.append(unit + ":" + active + "/" + (file_state or "-"))
        continue
    if load != "loaded":
        error("systemd:unit-load-" + (load if re.fullmatch(r"[a-z-]{1,32}", load) else "invalid"))
    if active in ACTIVE_STATES or file_state in ENABLED_STATES:
        bad_units.append(unit + ":" + (active or "-") + "/" + (file_state or "-"))
bad_ports = [str(port) + "/" + proto for proto, port in ports if listeners(proto, port)]
value = "units=" + (",".join(bad_units) or "-") + ";listeners=" + (",".join(bad_ports) or "-")
print("VALUE\t" + value + "\t" + ("FAIL" if bad_units or bad_ports else "PASS"))
SLP_NETWORK_SERVICE_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-TELNET' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-TELNET' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-TELNET' "ERROR" "${_slp_obs#ERROR$'\t'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-TELNET' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-11.2-TELNET' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

SLP_SYSTEM_ID=''
SLP_SYSTEM_VERSION_ID=''
SLP_SYSTEM_PRETTY_NAME=''
SLP_SYSTEM_ARCH=''
SLP_SYSTEM_PROFILE=''
SLP_SYSTEM_TYPE=''
SLP_SYSTEM_PLATFORM=''
SLP_SYSTEM_ENVIRONMENT=''
SLP_CLASSIFY_REASON=''

slp_classify_dpkg_status() {
  local _slp_out=$1 _slp_want='' _slp_eflag='' _slp_status='' _slp_extra=''
  [[ $_slp_out != *$'\n'* && $_slp_out != *$'\r'* ]] || return 1
  IFS=' ' read -r _slp_want _slp_eflag _slp_status _slp_extra <<< "$_slp_out"
  [[ -n $_slp_want && -n $_slp_eflag && -n $_slp_status && -z $_slp_extra ]] || return 1
  case "$_slp_want" in
    unknown|install|hold|deinstall|purge) ;;
    *) return 1 ;;
  esac
  [[ $_slp_eflag == ok ]] || return 1
  case "$_slp_status" in
    installed) printf '%s' installed ;;
    not-installed|config-files) printf '%s' absent ;;
    *) return 1 ;;
  esac
}

slp_dpkg_package_state() {
  local _slp_pkg=$1 _slp_out='' _slp_rc=0
  [[ -x /usr/bin/dpkg-query ]] || return 1
  _slp_out=$(LC_ALL=C command /usr/bin/dpkg-query --root=/ --admindir=/var/lib/dpkg -W -f='${Status}' -- "$_slp_pkg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc == 0 )); then
    slp_classify_dpkg_status "$_slp_out"
    return $?
  fi
  if (( _slp_rc == 1 )); then
    printf '%s' absent
    return 0
  fi
  return 1
}

slp_default_target_name() {
  # Читается только заданный администратором default.target (/etc, /run,
  # /usr/local/lib): поставляемое пакетом systemd значение
  # /usr/lib/systemd/system/default.target признаком рабочего стола не
  # является. Файл не найден: none; повреждённая ссылка или имя не
  # *.target: код 1.
  local _slp_t='' _slp_p=''
  for _slp_p in /etc/systemd/system/default.target /run/systemd/system/default.target /usr/local/lib/systemd/system/default.target; do
    [[ -e $_slp_p || -L $_slp_p ]] || continue
    [[ -L $_slp_p && ! -e $_slp_p ]] && return 1
    _slp_t=$(command /usr/bin/readlink -- "$_slp_p" 2>/dev/null) || return 1
    _slp_t=${_slp_t##*/}
    case "$_slp_t" in
      ''|*[!A-Za-z0-9_.-]*) return 1 ;;
      *.target) printf '%s' "$_slp_t"; return 0 ;;
      *) return 1 ;;
    esac
  done
  printf '%s' none
}

slp_classify_environment() {
  local _slp_id=$1 _slp_version=$2 _slp_arch=$3
  local _slp_server_minimal=$4 _slp_ubuntu_minimal=$5 _slp_ubuntu_standard=$6
  local _slp_desktop_pkg=$7 _slp_default_target=$8
  local _slp_profile='' _slp_type='' _slp_platform='' _slp_environment=''
  SLP_CLASSIFY_REASON=''
  SLP_SYSTEM_ID=$_slp_id
  SLP_SYSTEM_VERSION_ID=$_slp_version
  SLP_SYSTEM_ARCH=$_slp_arch
  SLP_SYSTEM_PROFILE=''
  SLP_SYSTEM_TYPE=''
  SLP_SYSTEM_PLATFORM=''
  SLP_SYSTEM_ENVIRONMENT=''
  _slp_platform="$_slp_id-$_slp_version-$_slp_arch"
  SLP_SYSTEM_PLATFORM=$_slp_platform
  if [[ $_slp_arch != x86_64 ]]; then
    SLP_SYSTEM_PROFILE=UNKNOWN
    SLP_CLASSIFY_REASON=PLATFORM
    return 0
  fi
  case "$_slp_id:$_slp_version" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)
      if [[ $_slp_server_minimal == installed ]]; then
        if [[ $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
          _slp_profile=FULL
        elif [[ $_slp_ubuntu_minimal == absent && $_slp_ubuntu_standard == absent ]]; then
          _slp_profile=MINIMIZED
        else
          SLP_SYSTEM_PROFILE=UNKNOWN
          SLP_CLASSIFY_REASON=PROFILE
          return 0
        fi
      elif [[ $_slp_server_minimal == absent && $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
        _slp_type=DESKTOP
      else
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
        return 0
      fi
      ;;
    debian:12|debian:13)
      if [[ $_slp_desktop_pkg != installed && $_slp_desktop_pkg != absent ]]; then
        SLP_SYSTEM_PROFILE=UNKNOWN
        SLP_CLASSIFY_REASON=PROFILE
        return 0
      fi
      if [[ $_slp_default_target != none && ( $_slp_default_target != *.target || $_slp_default_target == *[!A-Za-z0-9_.-]* ) ]]; then
        SLP_SYSTEM_PROFILE=UNKNOWN
        SLP_CLASSIFY_REASON=PROFILE
        return 0
      fi
      if [[ $_slp_desktop_pkg == installed || $_slp_default_target == graphical.target ]]; then
        _slp_type=DESKTOP
      else
        _slp_profile=SERVER
      fi
      ;;
    *)
      SLP_SYSTEM_PROFILE=UNKNOWN
      SLP_CLASSIFY_REASON=PLATFORM
      return 0
      ;;
  esac
  if [[ -n $_slp_type ]]; then
    _slp_environment="$_slp_platform-desktop"
  else
    _slp_environment="$_slp_platform-${_slp_profile,,}"
  fi
  case "$_slp_environment" in
    'ubuntu-22.04-x86_64-full'|'ubuntu-24.04-x86_64-minimized'|'ubuntu-24.04-x86_64-full'|'ubuntu-26.04-x86_64-minimized'|'ubuntu-26.04-x86_64-full'|'debian-12-x86_64-server'|'debian-13-x86_64-server')
      SLP_SYSTEM_PROFILE=$_slp_profile
      ;;
    'ubuntu-22.04-x86_64-desktop'|'ubuntu-24.04-x86_64-desktop'|'ubuntu-26.04-x86_64-desktop'|'debian-12-x86_64-desktop'|'debian-13-x86_64-desktop')
      # Десктопная среда распознана, но в проверенную серверную матрицу не
      # входит: проверки выполняются, отчёт помечает SUPPORT=UNSUPPORTED.
      SLP_SYSTEM_TYPE=$_slp_type
      ;;
    *)
      if [[ -n $_slp_type ]]; then
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
      else
        SLP_SYSTEM_PROFILE=UNKNOWN
        SLP_CLASSIFY_REASON=PROFILE
      fi
      return 0
      ;;
  esac
  SLP_SYSTEM_ENVIRONMENT=$_slp_environment
  return 0
}

slp_preflight_validate_text_bytes() {
  local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_n=0
  local _slp_v_need=0 _slp_v_min=128 _slp_v_max=191
  if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
  for _slp_v_byte in $_slp_v_hex; do
    [[ $_slp_v_byte =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
    case "$_slp_v_byte" in
      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f) return 1 ;;
    esac
    _slp_v_n=$((16#$_slp_v_byte))
    if (( _slp_v_need > 0 )); then
      (( _slp_v_n >= _slp_v_min && _slp_v_n <= _slp_v_max )) || return 1
      ((_slp_v_need-=1))
      _slp_v_min=128 _slp_v_max=191
      continue
    fi
    if (( _slp_v_n <= 127 )); then
      continue
    elif (( _slp_v_n >= 194 && _slp_v_n <= 223 )); then
      _slp_v_need=1
    elif (( _slp_v_n == 224 )); then
      _slp_v_need=2 _slp_v_min=160
    elif (( (_slp_v_n >= 225 && _slp_v_n <= 236) || (_slp_v_n >= 238 && _slp_v_n <= 239) )); then
      _slp_v_need=2
    elif (( _slp_v_n == 237 )); then
      _slp_v_need=2 _slp_v_max=159
    elif (( _slp_v_n == 240 )); then
      _slp_v_need=3 _slp_v_min=144
    elif (( _slp_v_n >= 241 && _slp_v_n <= 243 )); then
      _slp_v_need=3
    elif (( _slp_v_n == 244 )); then
      _slp_v_need=3 _slp_v_max=143
    else
      return 1
    fi
  done
  (( _slp_v_need == 0 )) || return 1
  return 0
}

SLP_OS_RELEASE_VALUE=''
SLP_OS_RELEASE_ID=''
SLP_OS_RELEASE_VERSION_ID=''
SLP_OS_RELEASE_PRETTY_NAME=''

slp_parse_os_release_value() {
  local LC_ALL=C
  local _slp_in=$1 _slp_mode=unquoted _slp_body='' _slp_out='' _slp_ch='' _slp_next=''
  local _slp_len=${#1}
  SLP_OS_RELEASE_VALUE=''
  if (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == '"' ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == '"' ]] || return 1
    _slp_mode=double
    _slp_body=${_slp_in:1:_slp_len-2}
  elif (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == "'" ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == "'" ]] || return 1
    _slp_mode=single
    _slp_body=${_slp_in:1:_slp_len-2}
  else
    _slp_body=$_slp_in
  fi
  if [[ $_slp_mode == single ]]; then
    [[ $_slp_body != *"'"* ]] || return 1
    SLP_OS_RELEASE_VALUE=$_slp_body
    return 0
  fi
  while [[ -n $_slp_body ]]; do
    _slp_ch=${_slp_body:0:1}
    _slp_body=${_slp_body:1}
    if [[ $_slp_ch == '\' ]]; then
      [[ -n $_slp_body ]] || return 1
      _slp_next=${_slp_body:0:1}
      if [[ $_slp_mode == double ]]; then
        case "$_slp_next" in
          '$'|'`'|'"'|'\') _slp_out+=$_slp_next; _slp_body=${_slp_body:1} ;;
          *) _slp_out+='\' ;;
        esac
      else
        _slp_out+=$_slp_next
        _slp_body=${_slp_body:1}
      fi
      continue
    fi
    if [[ $_slp_mode == double ]]; then
      case "$_slp_ch" in
        '"'|'$'|'`') return 1 ;;
      esac
    else
      case "$_slp_ch" in
        "'"|'"'|'$'|'`'|' '|$'\t'|';') return 1 ;;
      esac
    fi
    _slp_out+=$_slp_ch
  done
  SLP_OS_RELEASE_VALUE=$_slp_out
  return 0
}

slp_parse_os_release_file() {
  local _slp_p_path=$1 _slp_p_line='' _slp_p_key='' _slp_p_raw=''
  SLP_OS_RELEASE_ID=''
  SLP_OS_RELEASE_VERSION_ID=''
  SLP_OS_RELEASE_PRETTY_NAME=''
  while IFS= read -r _slp_p_line || [[ -n $_slp_p_line ]]; do
    [[ $_slp_p_line == *=* ]] || continue
    _slp_p_key=${_slp_p_line%%=*}
    case "$_slp_p_key" in
      ID|VERSION_ID|PRETTY_NAME)
        _slp_p_raw=${_slp_p_line#*=}
        slp_parse_os_release_value "$_slp_p_raw" || return 1
        case "$_slp_p_key" in
          ID) SLP_OS_RELEASE_ID=$SLP_OS_RELEASE_VALUE ;;
          VERSION_ID) SLP_OS_RELEASE_VERSION_ID=$SLP_OS_RELEASE_VALUE ;;
          PRETTY_NAME) SLP_OS_RELEASE_PRETTY_NAME=$SLP_OS_RELEASE_VALUE ;;
        esac
        ;;
    esac
  done < "$_slp_p_path"
  return 0
}

slp_target_preflight() {
  # Факты системы собираются по возможности; чекер не отказывает ни на одной
  # среде: вне матрицы выводится SUPPORT=UNSUPPORTED, проверки выполняются.
  local _slp_id='' _slp_version='' _slp_pretty='' _slp_arch='' _slp_vrc=0
  local _slp_server_minimal=na _slp_ubuntu_minimal=na _slp_ubuntu_standard=na
  local _slp_desktop_pkg=na _slp_default_target=na
  if [[ -r /etc/os-release ]]; then
    slp_preflight_validate_text_bytes /etc/os-release; _slp_vrc=$?
    if (( _slp_vrc == 0 )) && slp_parse_os_release_file /etc/os-release; then
      _slp_id=$SLP_OS_RELEASE_ID
      _slp_version=$SLP_OS_RELEASE_VERSION_ID
      _slp_pretty=$SLP_OS_RELEASE_PRETTY_NAME
    fi
  fi
  _slp_arch=$(command /usr/bin/uname -m 2>/dev/null) || _slp_arch=''
  [[ -n $_slp_id ]] || _slp_id=unknown
  [[ -n $_slp_version ]] || _slp_version=unknown
  [[ -n $_slp_arch ]] || _slp_arch=unknown
  if [[ $_slp_id == ubuntu ]]; then
    _slp_server_minimal=$(slp_dpkg_package_state ubuntu-server-minimal) || _slp_server_minimal=na
    _slp_ubuntu_minimal=$(slp_dpkg_package_state ubuntu-minimal) || _slp_ubuntu_minimal=na
    _slp_ubuntu_standard=$(slp_dpkg_package_state ubuntu-standard) || _slp_ubuntu_standard=na
  elif [[ $_slp_id == debian ]]; then
    _slp_desktop_pkg=$(slp_dpkg_package_state task-desktop) || _slp_desktop_pkg=na
    _slp_default_target=$(slp_default_target_name) || _slp_default_target=na
  fi
  slp_classify_environment "$_slp_id" "$_slp_version" "$_slp_arch" \
    "$_slp_server_minimal" "$_slp_ubuntu_minimal" "$_slp_ubuntu_standard" \
    "$_slp_desktop_pkg" "$_slp_default_target"
  [[ -n $_slp_pretty ]] || _slp_pretty="$_slp_id $_slp_version"
  SLP_SYSTEM_PRETTY_NAME=$_slp_pretty
  return 0
}

slp_list() {
  command /usr/bin/cat <<'SLP_LIST_EOF'
id                                                                    | source                         | control                                                               | layer
FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE                   | fstec-linux-2022 §2.1.1        | local-account-password-state                                          | fstec-core
FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN                                 | fstec-linux-2022 §2.1.2        | ssh-root-login                                                        | fstec-core
FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS                                | fstec-linux-2022 §2.2.1        | su-wheel-access                                                       | fstec-core
FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY                        | fstec-linux-2022 §2.2.2        | sudoers-reviewed-policy                                               | fstec-core
FSTEC-LINUX-2022-2.3.1-GROUP-MODE                                     | fstec-linux-2022 §2.3.1        | group-mode                                                            | fstec-core
FSTEC-LINUX-2022-2.3.1-PASSWD-MODE                                    | fstec-linux-2022 §2.3.1        | passwd-mode                                                           | fstec-core
FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX                                  | fstec-linux-2022 §2.3.1        | shadow-go-rwx                                                         | fstec-core
FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION         | fstec-linux-2022 §2.3.2        | running-process-paths-write-protection                                | fstec-core
FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION            | fstec-linux-2022 §2.3.3        | cron-command-paths-write-protection                                   | fstec-core
FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION             | fstec-linux-2022 §2.3.4        | sudo-root-command-files-protection                                    | fstec-core
FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION                 | fstec-linux-2022 §2.3.5        | startup-files-write-protection                                        | fstec-core
FSTEC-LINUX-2022-2.3.6-CRON-D                                         | fstec-linux-2022 §2.3.6        | cron-d                                                                | fstec-core
FSTEC-LINUX-2022-2.3.6-CRON-DAILY                                     | fstec-linux-2022 §2.3.6        | cron-daily                                                            | fstec-core
FSTEC-LINUX-2022-2.3.6-CRON-HOURLY                                    | fstec-linux-2022 §2.3.6        | cron-hourly                                                           | fstec-core
FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY                                   | fstec-linux-2022 §2.3.6        | cron-monthly                                                          | fstec-core
FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY                                    | fstec-linux-2022 §2.3.6        | cron-weekly                                                           | fstec-core
FSTEC-LINUX-2022-2.3.6-CRONTAB                                        | fstec-linux-2022 §2.3.6        | crontab                                                               | fstec-core
FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE                           | fstec-linux-2022 §2.3.7        | user-cron-files-mode                                                  | fstec-core
FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE                     | fstec-linux-2022 §2.3.8        | standard-system-paths-mode                                            | fstec-core
FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE                                 | fstec-linux-2022 §2.3.9        | suid-sgid-mode                                                        | fstec-core
FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE                     | fstec-linux-2022 §2.3.10       | home-sensitive-files-mode                                             | fstec-core
FSTEC-LINUX-2022-2.3.11-DIR-MODE                                      | fstec-linux-2022 §2.3.11       | dir-mode                                                              | fstec-core
FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE                         | fstec-linux-2022 §2.3.11       | home-directories-mode                                                 | fstec-core
FSTEC-LINUX-2022-2.3.11-HOME-MODE                                     | fstec-linux-2022 §2.3.11       | home-mode                                                             | fstec-core
FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT                                 | fstec-linux-2022 §2.4.1        | dmesg-restrict                                                        | fstec-core
FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT                                  | fstec-linux-2022 §2.4.2        | kptr-restrict                                                         | fstec-core
FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC                                  | fstec-linux-2022 §2.4.3        | init-on-alloc                                                         | fstec-core
FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE                                   | fstec-linux-2022 §2.4.4        | slab-nomerge                                                          | fstec-core
FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE                                    | fstec-linux-2022 §2.4.5        | iommu-force                                                           | fstec-core
FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH                              | fstec-linux-2022 §2.4.5        | iommu-passthrough                                                     | fstec-core
FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT                                   | fstec-linux-2022 §2.4.5        | iommu-strict                                                          | fstec-core
FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET                        | fstec-linux-2022 §2.4.6        | randomize-kstack-offset                                               | fstec-core
FSTEC-LINUX-2022-2.4.7-MITIGATIONS                                    | fstec-linux-2022 §2.4.7        | mitigations                                                           | fstec-core
FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN                                 | fstec-linux-2022 §2.4.8        | bpf-jit-harden                                                        | fstec-core
FSTEC-LINUX-2022-2.5.1-VSYSCALL                                       | fstec-linux-2022 §2.5.1        | vsyscall                                                              | fstec-core
FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID                            | fstec-linux-2022 §2.5.2        | perf-event-paranoid                                                   | fstec-core
FSTEC-LINUX-2022-2.5.3-DEBUGFS                                        | fstec-linux-2022 §2.5.3        | debugfs                                                               | fstec-core
FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED                            | fstec-linux-2022 §2.5.4        | kexec-load-disabled                                                   | fstec-core
FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES                            | fstec-linux-2022 §2.5.5        | max-user-namespaces                                                   | fstec-core
FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED                      | fstec-linux-2022 §2.5.6        | unprivileged-bpf-disabled                                             | fstec-core
FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD                       | fstec-linux-2022 §2.5.7        | unprivileged-userfaultfd                                              | fstec-core
FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD                                 | fstec-linux-2022 §2.5.8        | ldisc-autoload                                                        | fstec-core
FSTEC-LINUX-2022-2.5.9-TSX                                            | fstec-linux-2022 §2.5.9        | tsx                                                                   | fstec-core
FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR                                 | fstec-linux-2022 §2.5.10       | mmap-min-addr                                                         | fstec-core
FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE                            | fstec-linux-2022 §2.5.11       | randomize-va-space                                                    | fstec-core
FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE                                   | fstec-linux-2022 §2.6.1        | ptrace-scope                                                          | fstec-core
FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS                             | fstec-linux-2022 §2.6.2        | protected-symlinks                                                    | fstec-core
FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS                            | fstec-linux-2022 §2.6.3        | protected-hardlinks                                                   | fstec-core
FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS                                | fstec-linux-2022 §2.6.4        | protected-fifos                                                       | fstec-core
FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR                              | fstec-linux-2022 §2.6.5        | protected-regular                                                     | fstec-core
FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE                                  | fstec-linux-2022 §2.6.6        | suid-dumpable                                                         | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE                   | fstec-logging-2025 §app2:1     | auditd-package                                                        | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE                   | fstec-logging-2025 §app2:2     | auditd-service                                                        | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION          | fstec-logging-2025 §app2:3     | admin-space-left-action                                               | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION                 | fstec-logging-2025 §app2:3     | disk-full-action                                                      | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE                         | fstec-logging-2025 §app2:3     | log-file                                                              | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT                       | fstec-logging-2025 §app2:3     | log-format                                                            | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP                        | fstec-logging-2025 §app2:3     | log-group                                                             | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE                     | fstec-logging-2025 §app2:3     | max-log-file                                                          | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION              | fstec-logging-2025 §app2:3     | max-log-file-action                                                   | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS                         | fstec-logging-2025 §app2:3     | num-logs                                                              | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION                | fstec-logging-2025 §app2:3     | space-left-action                                                     | fstec-core
FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES                      | fstec-logging-2025 §app2:4     | audit-rules                                                           | fstec-core
FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE                        | fstec-logging-2025 §main:5     | audit-log-free-space                                                  | fstec-core
FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD                           | fstec-configuration-2026 §1.1  | encrypt-method                                                        | fstec-core
FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING                  | fstec-configuration-2026 §1.1  | existing-password-aging                                               | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS                            | fstec-configuration-2026 §1.1  | pass-max-days                                                         | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS                            | fstec-configuration-2026 §1.1  | pass-min-days                                                         | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE                            | fstec-configuration-2026 §1.1  | pass-warn-age                                                         | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT                        | fstec-configuration-2026 §1.1  | pwquality-dcredit                                                     | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT               | fstec-configuration-2026 §1.1  | pwquality-enforce-for-root                                            | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT                        | fstec-configuration-2026 §1.1  | pwquality-lcredit                                                     | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN                         | fstec-configuration-2026 §1.1  | pwquality-minlen                                                      | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT                        | fstec-configuration-2026 §1.1  | pwquality-ocredit                                                     | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY                          | fstec-configuration-2026 §1.1  | pwquality-retry                                                       | fstec-core
FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT                        | fstec-configuration-2026 §1.1  | pwquality-ucredit                                                     | fstec-core
FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT               | fstec-configuration-2026 §1.2  | pwhistory-enforce-for-root                                            | fstec-core
FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER                       | fstec-configuration-2026 §1.2  | pwhistory-remember                                                    | fstec-core
FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL                            | fstec-configuration-2026 §8.4  | ssh-log-level                                                         | fstec-core
FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION              | fstec-configuration-2026 §9.1  | ssh-password-authentication                                           | fstec-core
FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS               | fstec-configuration-2026 §9.1  | ssh-permit-empty-passwords                                            | fstec-core
FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN                    | fstec-configuration-2026 §9.1  | ssh-permit-root-login                                                 | fstec-core
RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION | fstec-configuration-2026 §9.1  | recommended-configuration-2026-9.1-ssh-kbd-interactive-authentication | recommended
FSTEC-CONFIGURATION-2026-11.2-FTP                                     | fstec-configuration-2026 §11.2 | ftp                                                                   | fstec-core
FSTEC-CONFIGURATION-2026-11.2-SNMP                                    | fstec-configuration-2026 §11.2 | snmp                                                                  | fstec-core
FSTEC-CONFIGURATION-2026-11.2-TELNET                                  | fstec-configuration-2026 §11.2 | telnet                                                                | fstec-core
SLP_LIST_EOF
}

slp_provenance_all() {
  command /usr/bin/cat <<'SLP_PROVENANCE_EOF'
{"adapter_contract_sha256":"b61bf8df26744aade1d1fc284c1e64e485ec1fca706312e237ad04cad257e0a0","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"041ed9a038bc735d4d9f3e0f95c956ae197365aed7c334daf60ecbe2bef76666","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0314e6c11e3d15574a17a6e6a0379dd96f4b815c209ffa4a34d0afb533a68f63","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","layer":"fstec-core","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"5b4104165197dbe1d068c86ca1a389312a1a9a7f1ff4010581358b1844867a6d","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"84904ae1e8c49a4f24c1e39b643d44b15cdbbaaef3a15c87fa23fed3b086e022","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","layer":"fstec-core","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0067b3c40bbb65a0fd07423689aa322834807e474f0a87d992e4e679da5cf6fe","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"54ed508c23f712069aebe797345cf5edf954be690ce99e562cdc5afb9fb3b7e8","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"19ba20db72ac9f80aad08aa197a6db925f059cfd6258992229d4d822fb1a2eac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"pam-wheel-root-member","expected_type":"string","expected_value":"auth required pam_wheel.so use_uid;wheel:root","index_id":"SRC-0003","layer":"fstec-core","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"RELEASE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"6b419ad3093a3634becefddda3418a247c81ecec42f8074978c17eefd08c7a95","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d86880404662da0e55e63a1490b310b394a8392ca4ba3e8ee980ed41abf06a00","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"f92b7c65155d2fe60c13e5d3dce291facead96affcb4a6f9956f85be021ac978","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7509b7d80d34eb317bf960351cd2fcecd7ed964bde6c293c7ee577f45b2189b0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"standard-rules-only","expected_type":"string","expected_value":"root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL","index_id":"SRC-0004","layer":"fstec-core","parameter_key":"user-specs","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"RELEASE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"c2ddb8b4643a5dac0996dc5bd6f250af8627d49a05e77ae1c5a7187d9ff85139","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"956008d60174d803f30d84131015702ef531ee9e0532b242f9a3a56d4bea0cb3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e642ca111817660456d8c2a9f205719d4f3274d56d0a3baba18e41788b05aa30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"12ceea94cf3912722efbb10a0173d2f6acf3ce13e0928035b385f63c899e01f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0640","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"c66c8f79a9f9157ff9c85ec9260dc9dbe4349f680dfed13f5ec2d01b5401a6fd","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"3c7cc24051e77604283860bd303724cc29f6dcc037d723467f05e81d9b0b80cf","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","layer":"fstec-core","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"RELEASE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"258c3f7b90293ac7ff06ee86bbf2c02b9d90bbb34c82031159fb575ccae879c1","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"ec323810d13e127d35f4b179fbd5b651ef69c23ff1512184ad2994c0c99b3295","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"0d9f4ff186f3304da76c7ffc181b9c80b3b66962cd844de21e6e7825d5643955","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1233f43249ff15020896d482ab820f5f1b0aaba08a41cd9a9b8ed856183cc3be","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","layer":"fstec-core","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"RELEASE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"a92c9fab9698e38d1a1834b52e989fc17e2c7baad8e7026d0481ad38e27a2210","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"39af5cfba8b7f5597693351fbc2d37d9a1f3df0efa3c62009cbd08001a131a5c","adapter_id":"product-sudo-root-command-files-protection-check-v2","adapter_implementation_sha256":"a813944e6f08ce1a6a290ed4b094f114be3ef50209812b44fab13bfcfac7661c","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6d64794b43477540cabfe861642eb85597a14e565a8af0fe0e041572b3e98b68","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w-conditional","expected_type":"string","expected_value":"owner-if-regular-user;go-w-if-other-write","index_id":"SRC-0008","layer":"fstec-core","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers","product_status":"RELEASE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"7a6a6669b29f3d46d2fb393f1c8277b879c313c385f4a3ae316c94453f72316e","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"010ab192406f5589d22be1ee93756378a9be2d57e00d8069d247ce752c699752","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"93e5192633d284d9272748063bb0b047108c303bc77aa21729c2c82f1a0d8116","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d92d47e065d5f64a34946143f7f8e57ff436d9439c1720e41d3c77b2e2185c57","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","layer":"fstec-core","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"RELEASE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1c5b353264030dcfbdf1d6d6f0cebe18b4e0e0b66cad5a4567d1cbb0b7f36469","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"42abb75c7ef704214114dee04997f64383de1049569d4b7049577265eed15371","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"94de7ae285f6ec4df63334a5f92f8bd16b91a0513e22d8a95cfe0e2d72068838","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"40bcf7f54293f77ce0ac0f595d590ff351e40dd2f35bac9d8c2e2e1f794b28a8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e7fcd7d9de1f2021f17043f302dc7b1422b44c67dcac0c0c23a7465ab21208d3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4768263b4db31032e27abc3aef54d131beb5faa605b01acd20c8ad236e11d43e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d50e07de9a8e1d3feaf89464fe5807c60eb0ce864931c5de0fbeea57cd48a485","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"161472a1d435b0949651bc77a7ee15fcc5a114fe47cebe820020a228d26e14b3","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"2b0588e59b83b0a769677a900840c525e0038f9bfb9b9f8e1e87a720ee462612","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2fdbc989c1448defba1514e4c0d9118795cc87142166b72ae6b8775242d57af8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","layer":"fstec-core","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"RELEASE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"e2099c6abb144a09eb4bf848bc47ebece27f053441d3bff7d1d58e23c2753c14","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"1abe9056e9454e4de579febc9fe0881cae9ea8947af233e97441731df39b85b9","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"7a7b29ec822a268c75ebe2c2abc25bcea8b1e28aeb2d3c33db4b6c8af5afaa2a","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"fc60c18b38228707f5885c13f1f16a89b3c2dca42a38e9c69effb3ceb7048216","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","layer":"fstec-core","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"RELEASE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"25f299cbc99954ce833035b017c42476383c81c49ccc76922c0499f5cecf4d04","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"db4be15ab3c65fc0a9b798e5b418efc9043691dc946f203b4a57f661aab00a16","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"2cdde7b64358b4426078c156c2c4c72b00d66edd5e6794e918a08b9b0aa6a470","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"181c86580d9111600a2e2e8661db62f61c8e0f05e8c4b4c119f27bdd2818dfc8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","layer":"fstec-core","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"RELEASE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ef443ec8cc04ab8e8195e25587eee01033f8367378a35131d9a98e1d9a1b5b0c","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"c97e0ac2eaad4ce524300b070e51b79716cca2d5b397a5514d91d2fa60d9c01a","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"b824ad8a6819d0037602f66e9526466887d83fa6071f4fe3f666781de461afb4","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b2e9e7b7bc2a3acdbf6e20be5406e2a74a367a75cdc5b0c172abc6a9bfa0f163","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","layer":"fstec-core","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/home","product_status":"RELEASE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"9707baf324a4cf8b2f0ed7826cbd55d1a2593282d5a7e97cacb16ca55f448360","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"08976aa44e4ff0afb5c6e0f89c65e10397d479b233be3be4f055fb111f206131","adapter_id":"product-adduser-conf-option-check-v1","adapter_implementation_sha256":"292c26d3681f6b7732fc4a40f91e10d86a4e6f1d6c4fe1772207eafdcc23e25d","control_id":"FSTEC-LINUX-2022-2.3.11-DIR-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"cba7056d6366cce57cce4bbc98e5179b42b0a8dcdbc2680205e9d75ee2590e74","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"DIR_MODE","parameter_kind":"adduser-conf-option","parameter_locator":"/etc/adduser.conf","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ce49192daa98c2096e85934e26f96895b3c3612780f84f20bbaa2cc1701658fa","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0eefcbb121ed839aaaa90ad852099e3e7d5fbd6f8698c6b111814abe21d71eb4","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"655bbd053502149785e86444dd5b123ad3ae0cb47ad3e4507227f572d720e424","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"21772226c90672954ddcdfe0aabf30309dc83cf6b5fc5de39bb8b248b24cd33d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/home","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"7bbc67aed77ec5b40665abb40e57106e1d729b143316e25b1a91c58fd1b5e480","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"09170974634017f1e2e544b51329fc8f084082fa4727468d2b1e3ae493c96b98","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"HOME_MODE","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"53f03ee29dfa574d13b10683fcdfe738cbd04629ba81fb1ec092bb1fc91ef49a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","layer":"fstec-core","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0a257a5fadad7de419ef47749abb09eba1721028b122080b90256e7d47d156d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","layer":"fstec-core","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1a20732ab081299b502577bff09076e0cac80d795e5e0f7dfa99d56b543eb6f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","layer":"fstec-core","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"42598531d328f70c985077c172050b942eb0383912f83f1fb3fcc3bceff866ae","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","layer":"fstec-core","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"de768afa461b5dac76760483f750d1c5d20a1e64cda8ce0a72f5fd1cf74f8935","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"faea7e28cf9f4358b4c4e91c802a07e7316dd42b8443099a4741cdf1fbe01488","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7d0d5f2e3b289189e06f78b1c4a33e8c4570bcec467d34986b7b916c7a68d354","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"403e9c13d75c6c0cd6aede3d002e1e82227f180d71cfef65017ab81b1e2dbd44","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","layer":"fstec-core","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e32cb42a14db86fc69a2c7960a07ef8398fb7079ae5ea839e377de7338ea55b5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","layer":"fstec-core","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"47b6b8e37bf7cc6065455bc2fe3607841eaf5c16cf1e748ac58c6a838c7d0132","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","layer":"fstec-core","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"74e099ee4df9dac18a3e2df48caa314926d3e72b7ea9e7783a4943f4b3d847c9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","layer":"fstec-core","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e7bce3ca88fe891571b2a31bac7b7e78a35e736cf4dbdc0f0de0c3278342dc6a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","layer":"fstec-core","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"84ae56f9c2362a51d053979a3f2eb982b4ca1ae43f2b227ef0477634d4beb292","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","layer":"fstec-core","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6e5edb1b1a4ae8d231abfb1aa6df0695b632d4ec4c36f9da1a98307b1526f6cf","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","layer":"fstec-core","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6eaa0334658fb48e9117a6dc17c96d66324ba94d9e7f6df4a08c6fe30ec14590","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","layer":"fstec-core","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"675490eca28c80f2bcaf85f3bfed38e0cd69f65a131133c5432deb9c3b34f73d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","layer":"fstec-core","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"655ca09fc55ba9c256a8c465c8e4e641880da38ae5ae1b54ca3c9131ddf1a097","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","layer":"fstec-core","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ebee2def369534141260369cab0c06590a2794552840614ed1c07c82706eac30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","layer":"fstec-core","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"494ea76e9e0e691222570f565c70b01f6a06e852ae4f851f3e8f65e95827fe19","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","layer":"fstec-core","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"a78e5d528693d8981244270851b0e562063b021045e56f9b58fd855c82760818","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","layer":"fstec-core","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c5d4a6d65c18a1a12d68d14594f93bf6d33fc0c3e8f18b8a5333d3ad7ae9ea70","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","layer":"fstec-core","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5c929cb7994116522a03e040af9e13dea447478d632cf58e45baac64d844cda7","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","layer":"fstec-core","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9109618bf48e0d314306aa7165c39dc78e16de398f77ce534fffa464c2b850f1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","layer":"fstec-core","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0e8844a89ff5c2678009b8c27d3f031a778e2a8b9753f93a8901f450e07fa80f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","layer":"fstec-core","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5510b1f68c078e769ab1b29775eef8500f102d68982db8c13a5f444e6a7a7f03","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","layer":"fstec-core","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9bfd2d1c3ae0ee3c48f6405a07e21e85da430418929147834bfbf83f82fc1791","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","layer":"fstec-core","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"cee0ebd9587fda4e329e2759b697db93a8eff99cfe287207831670b86ed63350","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","layer":"fstec-core","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"9f5d1fdffa1e03ff797f728d8c230ad19908b47e13130ec5102aa405500e4fc4","adapter_id":"product-auditd-package-service-check-v1","adapter_implementation_sha256":"36dff1942db7a220e6bdafec88526fa883f53fecf054a221080a2672611854d4","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ed62bb3e204a515008d85aaa43b63401686e160861c668a5e6e1887a23730755","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"installed","index_id":"SRC-0050","layer":"fstec-core","parameter_key":"package","parameter_kind":"auditd-package-service","parameter_locator":"dpkg|systemd","product_status":"RELEASE","quote_sha256":"8858c54f4b5a960d6448e8724475ab5387ca4f51aef9a8b2c41342f875007a32","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1d22502fd96bd402bd1efe60d470649bb5150e0da1d5365e9b333eccde58501c","source_locator":"appendix2-linux:1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"9f5d1fdffa1e03ff797f728d8c230ad19908b47e13130ec5102aa405500e4fc4","adapter_id":"product-auditd-package-service-check-v1","adapter_implementation_sha256":"36dff1942db7a220e6bdafec88526fa883f53fecf054a221080a2672611854d4","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7bf9aed2d479ef42256a1eb5f932a4389d3975d2b17479b5f7d0ad6e989838ee","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"enabled-active","index_id":"SRC-0051","layer":"fstec-core","parameter_key":"service","parameter_kind":"auditd-package-service","parameter_locator":"dpkg|systemd","product_status":"RELEASE","quote_sha256":"ccf43e6cc8c852b7c386d7540313589fa6b97536e9170d94a80751e60d1c25bf","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1d22502fd96bd402bd1efe60d470649bb5150e0da1d5365e9b333eccde58501c","source_locator":"appendix2-linux:2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d2204c250c1fe9b55c9dc56b36a3f2388f71d4aaeaa01880697a40e3bf8577a4","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"suspend","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"admin_space_left_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f9121cc7f3a35e2e235ef0c7e5349c0d0deb4bf8ec176044f4e0b5d6e4523d67","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"suspend","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"disk_full_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"29eb7aefd3f57eebc759b1898c8e7d5b4ad24ac7bbef3e2eb4e22d0f4b144e86","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"/var/log/audit/audit.log","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_file","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"93216147fe6eecc8190dfe95102545f64cf9aeb66c9127ecef3eec689bdb09a6","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"ENRICHED","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_format","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5571a4ed49110934c45e336aa698ecdb342cc72c879abcc89ce280007736bb12","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"root","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_group","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c141ad28a2a00f68ecf261ca8e439325fbd1d7869f80ea4b9d36eb39534d3c57","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"50","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"max_log_file","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"3dc633e5301a045829ae04a553aaad3fc1724ef83ab6b03b4cf79a84b3185799","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"rotate","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"max_log_file_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2a53733a4956d77da37e1d7350c72b89858047221ef191d2566bd2c79323cae5","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"150","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"num_logs","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b52e433180e03ba441fbf2a599922454cc99a378c2514ee760c824145daec5bf","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"syslog","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"space_left_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b51e408501ce85bff02266c7c83dd9dc1fc3e19c3d6a36534cd6eb109d19a272","adapter_id":"product-auditd-rules-check-v1","adapter_implementation_sha256":"df11ea73ace502d05c45ef7da9e3fb0287165aab84a4c5237a321a26b4e5bf8e","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f535544323987db0a811197a6333c43e3aff3066080bbfa3ff222a44a838eb68","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"present","index_id":"SRC-0053","layer":"fstec-core","parameter_key":"table1","parameter_kind":"auditd-rules","parameter_locator":"/etc/audit/rules.d","product_status":"RELEASE","quote_sha256":"e2f6793302a08482b131be9de48d895e139103ed28a598a75ba09b6cdbee212e","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"a381e8ee96d39b4bff501bb42c9005b2060288d481a81ef2bba6d984e1115996","source_locator":"appendix2-linux:4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4030e63e9eb42f5cea5d453bd886e22817f316489c17093281a06829b434b29b","adapter_id":"product-auditd-log-free-space-check-v1","adapter_implementation_sha256":"de6f2872ec46e6556f7250ee1cb8d0f175ead74f654b2bb5d2091f8291163447","control_id":"FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"32ef02a7b73e505f582ed861468c9018a1534d9821906e01e2c73fc4fc152120","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"ge","expected_type":"integer","expected_value":7516192768,"index_id":"SRC-0045","layer":"fstec-core","parameter_key":"available_bytes","parameter_kind":"auditd-log-free-space","parameter_locator":"/var/log/audit","product_status":"RELEASE","quote_sha256":"372ae998b49be4a847cc25bb8228c6d12fe92148df9282ce1b302a1757e8eb1c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"c50eb2248e8cd06d902761a7974bf0207282b41517d2f310a44fc117d037af0a","source_locator":"main:5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e0aaa44466449c3a184eb437c473d087002a7dbbf92a4b3cddb01ed4a48600ff","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"one-of","expected_type":"string","expected_value":"SHA512|YESCRYPT","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ENCRYPT_METHOD","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"c7e7801017473b39e861e6c56d3e50c212a9b6c2f0b85714cf1a38cffe98c9c8","adapter_id":"product-local-account-password-aging-check-v1","adapter_implementation_sha256":"1e5d5e91703ccb5e3c7652c4398be12f50759c3d15af473b05d203b71f0383c0","control_id":"FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6a9e72dc4e8502ab8b1877f610df0dcd54ae3529ea23748715008edfda0135d4","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"1/90/7","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"aging-fields","parameter_kind":"local-account-password-aging","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"b1ccadcb57aa2db8a2f84d67b8b4cb202ccafe8834efe5a9120c52f2ca43b580","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"8bde26edc3fcd532874c5be570cf4e3339749ab68375453723ce991d73d9bdaa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"90","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_MAX_DAYS","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"704c704d3c84c58f5cfb5dcc5372d87db66a7a4fa8f0051643a08a4cbf8ab9a5","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_MIN_DAYS","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"74d7bae596945e5654deec69c6fbd7945fce969b55fde431e02e8d9730b99bb5","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"7","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_WARN_AGE","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"67cbaaa9df5e98fcd12c96ba92d02e957efa22074ccb33a3820db7f13f73afbe","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"dcredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1aff5be225b04b25fc448d994428c5d0c081120ab56d2e0834576dea6d5e7982","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"enforce_for_root","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"8832241ba830a475148e27c3e437a5462face59f7256193684bfa1e6d4db5086","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"lcredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f33c9b1a8a94c4c8b52c67c10cc606c4c039cac9cf0e3ed28d36984258c8b5ec","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"ge","expected_type":"integer","expected_value":12,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"minlen","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b74080352b7d7530f3cedc2792d179567a299ef2c2625d0e3d55da88b6aa04d","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ocredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b92fa23522ea192c73d823fba595c11a493122883c116c53cc900c1cff02b11","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"retry","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e422ad1e82c1d3bb471800da1820dccc8e28ba4cfc0811aa038cfffa7f341154","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ucredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"be4c65241b45bf9b9695d078f1febb54f849ee6461dfc6b18a900dfb96cc5cd4","adapter_id":"product-pam-pwhistory-remember-check-v1","adapter_implementation_sha256":"60f82120ba7786fe9f156ab5cedee420f82f2576324d7c5924f23fafb663c4fd","control_id":"FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"fb81ed55cf5d47444ef18819fd9af29599c0878e6496b1f864d221096829a743","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0056","layer":"fstec-core","parameter_key":"enforce_for_root","parameter_kind":"pam-pwhistory-remember","parameter_locator":"/etc/pam.d/common-password","product_status":"RELEASE","quote_sha256":"d7fc2ec1e041a96c320f1355a99ddd18b8110bb98355e7579da29c09aa3b623d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"3c41ce785fe6d1fb873cb32c6cda1954f2f28f384ef5175a8bcfea6d6e19bd60","source_locator":"1.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"be4c65241b45bf9b9695d078f1febb54f849ee6461dfc6b18a900dfb96cc5cd4","adapter_id":"product-pam-pwhistory-remember-check-v1","adapter_implementation_sha256":"60f82120ba7786fe9f156ab5cedee420f82f2576324d7c5924f23fafb663c4fd","control_id":"FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b91bc68c49dc3fd272b0cd9bb048e6a08be3c00eaf54549303536be12a1eab81","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"ge","expected_type":"integer","expected_value":5,"index_id":"SRC-0056","layer":"fstec-core","parameter_key":"remember","parameter_kind":"pam-pwhistory-remember","parameter_locator":"/etc/pam.d/common-password","product_status":"RELEASE","quote_sha256":"d7fc2ec1e041a96c320f1355a99ddd18b8110bb98355e7579da29c09aa3b623d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"3c41ce785fe6d1fb873cb32c6cda1954f2f28f384ef5175a8bcfea6d6e19bd60","source_locator":"1.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5b24302f05d5e939a14c799b3a6a6ebb9cf95cd4d360aef68be75b658ec3eb6b","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"VERBOSE","index_id":"SRC-0091","layer":"fstec-core","parameter_key":"LogLevel","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"a40740a4d2f728fd1f16a2e48ceb6c2ee8a49ec3eefa633d17b13af7863411c6","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"8.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"76f8526661cb3c9854c2e8436d98649482a2be5a6bc4e7b953ac97db71a5a5aa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PasswordAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"eb6ea9f476a6b65ef758631f9a920e5c9af3d1f7b136145f2727991641c88055","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PermitEmptyPasswords","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ff7f9436907ec698f6298a7d3a5a785da36399228a0f213295ec0626303c8cd2","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PermitRootLogin","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f6a5107dbd68d885e0ea4fc526a4525b4c19fdb02a69da1bbc302c061e3072c8","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"recommended","parameter_key":"KbdInteractiveAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-FTP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4e1b1a63aabb01c3ee3281d8d07dab5c6e39353ade2ddbaead0b8c1dbc7963a1","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"ftp","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-SNMP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c892a0edd6da6fa55ee77205d5f10f08fe5e7152a960bd92b2ddde100e6c00b0","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"snmp","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-TELNET","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b84a63eb9852a42dd1b692e72062137d23e83c817b6d5d1e72db24d26f35ec8","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"telnet","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  # Код 2: контроль не найден (без вывода); сбой записи с любым кодом: код 1.
  case "$1" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s\n' '{"adapter_contract_sha256":"b61bf8df26744aade1d1fc284c1e64e485ec1fca706312e237ad04cad257e0a0","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"041ed9a038bc735d4d9f3e0f95c956ae197365aed7c334daf60ecbe2bef76666","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0314e6c11e3d15574a17a6e6a0379dd96f4b815c209ffa4a34d0afb533a68f63","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","layer":"fstec-core","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"5b4104165197dbe1d068c86ca1a389312a1a9a7f1ff4010581358b1844867a6d","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"84904ae1e8c49a4f24c1e39b643d44b15cdbbaaef3a15c87fa23fed3b086e022","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","layer":"fstec-core","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s\n' '{"adapter_contract_sha256":"0067b3c40bbb65a0fd07423689aa322834807e474f0a87d992e4e679da5cf6fe","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"54ed508c23f712069aebe797345cf5edf954be690ce99e562cdc5afb9fb3b7e8","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"19ba20db72ac9f80aad08aa197a6db925f059cfd6258992229d4d822fb1a2eac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"pam-wheel-root-member","expected_type":"string","expected_value":"auth required pam_wheel.so use_uid;wheel:root","index_id":"SRC-0003","layer":"fstec-core","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"RELEASE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"6b419ad3093a3634becefddda3418a247c81ecec42f8074978c17eefd08c7a95","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s\n' '{"adapter_contract_sha256":"d86880404662da0e55e63a1490b310b394a8392ca4ba3e8ee980ed41abf06a00","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"f92b7c65155d2fe60c13e5d3dce291facead96affcb4a6f9956f85be021ac978","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7509b7d80d34eb317bf960351cd2fcecd7ed964bde6c293c7ee577f45b2189b0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"standard-rules-only","expected_type":"string","expected_value":"root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL","index_id":"SRC-0004","layer":"fstec-core","parameter_key":"user-specs","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"RELEASE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"c2ddb8b4643a5dac0996dc5bd6f250af8627d49a05e77ae1c5a7187d9ff85139","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"956008d60174d803f30d84131015702ef531ee9e0532b242f9a3a56d4bea0cb3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e642ca111817660456d8c2a9f205719d4f3274d56d0a3baba18e41788b05aa30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"12ceea94cf3912722efbb10a0173d2f6acf3ce13e0928035b385f63c899e01f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0640","index_id":"SRC-0005","layer":"fstec-core","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"c66c8f79a9f9157ff9c85ec9260dc9dbe4349f680dfed13f5ec2d01b5401a6fd","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"3c7cc24051e77604283860bd303724cc29f6dcc037d723467f05e81d9b0b80cf","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","layer":"fstec-core","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"RELEASE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"258c3f7b90293ac7ff06ee86bbf2c02b9d90bbb34c82031159fb575ccae879c1","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"ec323810d13e127d35f4b179fbd5b651ef69c23ff1512184ad2994c0c99b3295","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"0d9f4ff186f3304da76c7ffc181b9c80b3b66962cd844de21e6e7825d5643955","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1233f43249ff15020896d482ab820f5f1b0aaba08a41cd9a9b8ed856183cc3be","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","layer":"fstec-core","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"RELEASE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"a92c9fab9698e38d1a1834b52e989fc17e2c7baad8e7026d0481ad38e27a2210","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"39af5cfba8b7f5597693351fbc2d37d9a1f3df0efa3c62009cbd08001a131a5c","adapter_id":"product-sudo-root-command-files-protection-check-v2","adapter_implementation_sha256":"a813944e6f08ce1a6a290ed4b094f114be3ef50209812b44fab13bfcfac7661c","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6d64794b43477540cabfe861642eb85597a14e565a8af0fe0e041572b3e98b68","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w-conditional","expected_type":"string","expected_value":"owner-if-regular-user;go-w-if-other-write","index_id":"SRC-0008","layer":"fstec-core","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers","product_status":"RELEASE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"7a6a6669b29f3d46d2fb393f1c8277b879c313c385f4a3ae316c94453f72316e","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"010ab192406f5589d22be1ee93756378a9be2d57e00d8069d247ce752c699752","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"93e5192633d284d9272748063bb0b047108c303bc77aa21729c2c82f1a0d8116","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d92d47e065d5f64a34946143f7f8e57ff436d9439c1720e41d3c77b2e2185c57","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","layer":"fstec-core","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"RELEASE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1c5b353264030dcfbdf1d6d6f0cebe18b4e0e0b66cad5a4567d1cbb0b7f36469","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"42abb75c7ef704214114dee04997f64383de1049569d4b7049577265eed15371","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"94de7ae285f6ec4df63334a5f92f8bd16b91a0513e22d8a95cfe0e2d72068838","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"40bcf7f54293f77ce0ac0f595d590ff351e40dd2f35bac9d8c2e2e1f794b28a8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e7fcd7d9de1f2021f17043f302dc7b1422b44c67dcac0c0c23a7465ab21208d3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4768263b4db31032e27abc3aef54d131beb5faa605b01acd20c8ad236e11d43e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s\n' '{"adapter_contract_sha256":"8a7382ed09e32878f2436c9ceffdb99874b7445a6a0b4b377447a797d8220801","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"54c7a96f16151edd1e5fa1122b0bf122b5c813a47d7ba9e35ae5050193d7967c","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d50e07de9a8e1d3feaf89464fe5807c60eb0ce864931c5de0fbeea57cd48a485","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","layer":"fstec-core","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"RELEASE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"161472a1d435b0949651bc77a7ee15fcc5a114fe47cebe820020a228d26e14b3","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"2b0588e59b83b0a769677a900840c525e0038f9bfb9b9f8e1e87a720ee462612","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2fdbc989c1448defba1514e4c0d9118795cc87142166b72ae6b8775242d57af8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","layer":"fstec-core","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"RELEASE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"e2099c6abb144a09eb4bf848bc47ebece27f053441d3bff7d1d58e23c2753c14","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s\n' '{"adapter_contract_sha256":"1abe9056e9454e4de579febc9fe0881cae9ea8947af233e97441731df39b85b9","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"7a7b29ec822a268c75ebe2c2abc25bcea8b1e28aeb2d3c33db4b6c8af5afaa2a","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"fc60c18b38228707f5885c13f1f16a89b3c2dca42a38e9c69effb3ceb7048216","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","layer":"fstec-core","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"RELEASE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"25f299cbc99954ce833035b017c42476383c81c49ccc76922c0499f5cecf4d04","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s\n' '{"adapter_contract_sha256":"db4be15ab3c65fc0a9b798e5b418efc9043691dc946f203b4a57f661aab00a16","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"2cdde7b64358b4426078c156c2c4c72b00d66edd5e6794e918a08b9b0aa6a470","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"181c86580d9111600a2e2e8661db62f61c8e0f05e8c4b4c119f27bdd2818dfc8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","layer":"fstec-core","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"RELEASE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ef443ec8cc04ab8e8195e25587eee01033f8367378a35131d9a98e1d9a1b5b0c","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"c97e0ac2eaad4ce524300b070e51b79716cca2d5b397a5514d91d2fa60d9c01a","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"b824ad8a6819d0037602f66e9526466887d83fa6071f4fe3f666781de461afb4","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b2e9e7b7bc2a3acdbf6e20be5406e2a74a367a75cdc5b0c172abc6a9bfa0f163","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","layer":"fstec-core","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/home","product_status":"RELEASE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"9707baf324a4cf8b2f0ed7826cbd55d1a2593282d5a7e97cacb16ca55f448360","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.11-DIR-MODE') printf '%s\n' '{"adapter_contract_sha256":"08976aa44e4ff0afb5c6e0f89c65e10397d479b233be3be4f055fb111f206131","adapter_id":"product-adduser-conf-option-check-v1","adapter_implementation_sha256":"292c26d3681f6b7732fc4a40f91e10d86a4e6f1d6c4fe1772207eafdcc23e25d","control_id":"FSTEC-LINUX-2022-2.3.11-DIR-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"cba7056d6366cce57cce4bbc98e5179b42b0a8dcdbc2680205e9d75ee2590e74","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"DIR_MODE","parameter_kind":"adduser-conf-option","parameter_locator":"/etc/adduser.conf","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ce49192daa98c2096e85934e26f96895b3c3612780f84f20bbaa2cc1701658fa","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s\n' '{"adapter_contract_sha256":"0eefcbb121ed839aaaa90ad852099e3e7d5fbd6f8698c6b111814abe21d71eb4","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"655bbd053502149785e86444dd5b123ad3ae0cb47ad3e4507227f572d720e424","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"21772226c90672954ddcdfe0aabf30309dc83cf6b5fc5de39bb8b248b24cd33d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/home","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"7bbc67aed77ec5b40665abb40e57106e1d729b143316e25b1a91c58fd1b5e480","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-MODE') printf '%s\n' '{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-MODE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"09170974634017f1e2e544b51329fc8f084082fa4727468d2b1e3ae493c96b98","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","layer":"fstec-core","parameter_key":"HOME_MODE","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"53f03ee29dfa574d13b10683fcdfe738cbd04629ba81fb1ec092bb1fc91ef49a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","layer":"fstec-core","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0a257a5fadad7de419ef47749abb09eba1721028b122080b90256e7d47d156d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","layer":"fstec-core","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1a20732ab081299b502577bff09076e0cac80d795e5e0f7dfa99d56b543eb6f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","layer":"fstec-core","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"42598531d328f70c985077c172050b942eb0383912f83f1fb3fcc3bceff866ae","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","layer":"fstec-core","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"de768afa461b5dac76760483f750d1c5d20a1e64cda8ce0a72f5fd1cf74f8935","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"faea7e28cf9f4358b4c4e91c802a07e7316dd42b8443099a4741cdf1fbe01488","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7d0d5f2e3b289189e06f78b1c4a33e8c4570bcec467d34986b7b916c7a68d354","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","layer":"fstec-core","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"403e9c13d75c6c0cd6aede3d002e1e82227f180d71cfef65017ab81b1e2dbd44","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","layer":"fstec-core","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e32cb42a14db86fc69a2c7960a07ef8398fb7079ae5ea839e377de7338ea55b5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","layer":"fstec-core","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"47b6b8e37bf7cc6065455bc2fe3607841eaf5c16cf1e748ac58c6a838c7d0132","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","layer":"fstec-core","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"74e099ee4df9dac18a3e2df48caa314926d3e72b7ea9e7783a4943f4b3d847c9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","layer":"fstec-core","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e7bce3ca88fe891571b2a31bac7b7e78a35e736cf4dbdc0f0de0c3278342dc6a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","layer":"fstec-core","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"84ae56f9c2362a51d053979a3f2eb982b4ca1ae43f2b227ef0477634d4beb292","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","layer":"fstec-core","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6e5edb1b1a4ae8d231abfb1aa6df0695b632d4ec4c36f9da1a98307b1526f6cf","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","layer":"fstec-core","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6eaa0334658fb48e9117a6dc17c96d66324ba94d9e7f6df4a08c6fe30ec14590","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","layer":"fstec-core","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"675490eca28c80f2bcaf85f3bfed38e0cd69f65a131133c5432deb9c3b34f73d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","layer":"fstec-core","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"655ca09fc55ba9c256a8c465c8e4e641880da38ae5ae1b54ca3c9131ddf1a097","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","layer":"fstec-core","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ebee2def369534141260369cab0c06590a2794552840614ed1c07c82706eac30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","layer":"fstec-core","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s\n' '{"adapter_contract_sha256":"85a20a5fb1f5f0bf08692343e950c33526dc3181929b5600f81a5099a46e7c63","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"e215aa0198a09c2a2eca16f759800da34f525675c4d3d1312fcc23955aa9e90a","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"494ea76e9e0e691222570f565c70b01f6a06e852ae4f851f3e8f65e95827fe19","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","layer":"fstec-core","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"RELEASE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"72bb59c6c5277f47e359d5a9e93a19263f94dd44706009205dccc35961900249","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"a78e5d528693d8981244270851b0e562063b021045e56f9b58fd855c82760818","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","layer":"fstec-core","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c5d4a6d65c18a1a12d68d14594f93bf6d33fc0c3e8f18b8a5333d3ad7ae9ea70","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","layer":"fstec-core","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5c929cb7994116522a03e040af9e13dea447478d632cf58e45baac64d844cda7","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","layer":"fstec-core","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9109618bf48e0d314306aa7165c39dc78e16de398f77ce534fffa464c2b850f1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","layer":"fstec-core","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"0e8844a89ff5c2678009b8c27d3f031a778e2a8b9753f93a8901f450e07fa80f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","layer":"fstec-core","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5510b1f68c078e769ab1b29775eef8500f102d68982db8c13a5f444e6a7a7f03","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","layer":"fstec-core","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9bfd2d1c3ae0ee3c48f6405a07e21e85da430418929147834bfbf83f82fc1791","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","layer":"fstec-core","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s\n' '{"adapter_contract_sha256":"4e8cd9596bf451069368b68b147131a6000767672e3b5b0436e8c28627621ec2","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"834970b4ee028e2540df5617c1d8e903753cf479c0298015a1dab78dbf89431a","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"cee0ebd9587fda4e329e2759b697db93a8eff99cfe287207831670b86ed63350","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","layer":"fstec-core","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"RELEASE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"ddc2755b6d58fa070a97d430d73e47ca1738934271e4f2b39c7718a3ee005541","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE') printf '%s\n' '{"adapter_contract_sha256":"9f5d1fdffa1e03ff797f728d8c230ad19908b47e13130ec5102aa405500e4fc4","adapter_id":"product-auditd-package-service-check-v1","adapter_implementation_sha256":"36dff1942db7a220e6bdafec88526fa883f53fecf054a221080a2672611854d4","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ed62bb3e204a515008d85aaa43b63401686e160861c668a5e6e1887a23730755","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"installed","index_id":"SRC-0050","layer":"fstec-core","parameter_key":"package","parameter_kind":"auditd-package-service","parameter_locator":"dpkg|systemd","product_status":"RELEASE","quote_sha256":"8858c54f4b5a960d6448e8724475ab5387ca4f51aef9a8b2c41342f875007a32","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1d22502fd96bd402bd1efe60d470649bb5150e0da1d5365e9b333eccde58501c","source_locator":"appendix2-linux:1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE') printf '%s\n' '{"adapter_contract_sha256":"9f5d1fdffa1e03ff797f728d8c230ad19908b47e13130ec5102aa405500e4fc4","adapter_id":"product-auditd-package-service-check-v1","adapter_implementation_sha256":"36dff1942db7a220e6bdafec88526fa883f53fecf054a221080a2672611854d4","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"7bf9aed2d479ef42256a1eb5f932a4389d3975d2b17479b5f7d0ad6e989838ee","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"enabled-active","index_id":"SRC-0051","layer":"fstec-core","parameter_key":"service","parameter_kind":"auditd-package-service","parameter_locator":"dpkg|systemd","product_status":"RELEASE","quote_sha256":"ccf43e6cc8c852b7c386d7540313589fa6b97536e9170d94a80751e60d1c25bf","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"1d22502fd96bd402bd1efe60d470649bb5150e0da1d5365e9b333eccde58501c","source_locator":"appendix2-linux:2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"d2204c250c1fe9b55c9dc56b36a3f2388f71d4aaeaa01880697a40e3bf8577a4","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"suspend","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"admin_space_left_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f9121cc7f3a35e2e235ef0c7e5349c0d0deb4bf8ec176044f4e0b5d6e4523d67","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"suspend","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"disk_full_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"29eb7aefd3f57eebc759b1898c8e7d5b4ad24ac7bbef3e2eb4e22d0f4b144e86","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"/var/log/audit/audit.log","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_file","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"93216147fe6eecc8190dfe95102545f64cf9aeb66c9127ecef3eec689bdb09a6","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"ENRICHED","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_format","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5571a4ed49110934c45e336aa698ecdb342cc72c879abcc89ce280007736bb12","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"root","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"log_group","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c141ad28a2a00f68ecf261ca8e439325fbd1d7869f80ea4b9d36eb39534d3c57","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"50","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"max_log_file","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"3dc633e5301a045829ae04a553aaad3fc1724ef83ab6b03b4cf79a84b3185799","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"rotate","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"max_log_file_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"2a53733a4956d77da37e1d7350c72b89858047221ef191d2566bd2c79323cae5","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"150","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"num_logs","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION') printf '%s\n' '{"adapter_contract_sha256":"8d5df91632bfa32b0167b4dd2b7d380b0f01355bcf89781dcbd0fae685361d51","adapter_id":"product-auditd-conf-option-check-v1","adapter_implementation_sha256":"cf42364ca3165a6bab9950f0d6cf0a675b09739baa589785cca45de5db8fdd1d","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b52e433180e03ba441fbf2a599922454cc99a378c2514ee760c824145daec5bf","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"syslog","index_id":"SRC-0052","layer":"fstec-core","parameter_key":"space_left_action","parameter_kind":"auditd-conf-option","parameter_locator":"/etc/audit/auditd.conf","product_status":"RELEASE","quote_sha256":"5083075ca7cdb820508651c79709b71f16d69f48d13beddfc49f9718b986d89d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"dfea250f7e229a3bfda4e72f308a6f2f3763ea7ae76b69b470f5cd89eec27991","source_locator":"appendix2-linux:3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES') printf '%s\n' '{"adapter_contract_sha256":"b51e408501ce85bff02266c7c83dd9dc1fc3e19c3d6a36534cd6eb109d19a272","adapter_id":"product-auditd-rules-check-v1","adapter_implementation_sha256":"df11ea73ace502d05c45ef7da9e3fb0287165aab84a4c5237a321a26b4e5bf8e","control_id":"FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f535544323987db0a811197a6333c43e3aff3066080bbfa3ff222a44a838eb68","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"eq","expected_type":"string","expected_value":"present","index_id":"SRC-0053","layer":"fstec-core","parameter_key":"table1","parameter_kind":"auditd-rules","parameter_locator":"/etc/audit/rules.d","product_status":"RELEASE","quote_sha256":"e2f6793302a08482b131be9de48d895e139103ed28a598a75ba09b6cdbee212e","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"a381e8ee96d39b4bff501bb42c9005b2060288d481a81ef2bba6d984e1115996","source_locator":"appendix2-linux:4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE') printf '%s\n' '{"adapter_contract_sha256":"4030e63e9eb42f5cea5d453bd886e22817f316489c17093281a06829b434b29b","adapter_id":"product-auditd-log-free-space-check-v1","adapter_implementation_sha256":"de6f2872ec46e6556f7250ee1cb8d0f175ead74f654b2bb5d2091f8291163447","control_id":"FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"32ef02a7b73e505f582ed861468c9018a1534d9821906e01e2c73fc4fc152120","doc_id":"fstec-logging-2025","doc_sha256":"2db44a4eebf1ec87986e0aea43f7b1c907e4ef21c052f01a2879e6d458a28a64","expected_op":"ge","expected_type":"integer","expected_value":7516192768,"index_id":"SRC-0045","layer":"fstec-core","parameter_key":"available_bytes","parameter_kind":"auditd-log-free-space","parameter_locator":"/var/log/audit","product_status":"RELEASE","quote_sha256":"372ae998b49be4a847cc25bb8228c6d12fe92148df9282ce1b302a1757e8eb1c","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"c50eb2248e8cd06d902761a7974bf0207282b41517d2f310a44fc117d037af0a","source_locator":"main:5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD') printf '%s\n' '{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e0aaa44466449c3a184eb437c473d087002a7dbbf92a4b3cddb01ed4a48600ff","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"one-of","expected_type":"string","expected_value":"SHA512|YESCRYPT","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ENCRYPT_METHOD","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING') printf '%s\n' '{"adapter_contract_sha256":"c7e7801017473b39e861e6c56d3e50c212a9b6c2f0b85714cf1a38cffe98c9c8","adapter_id":"product-local-account-password-aging-check-v1","adapter_implementation_sha256":"1e5d5e91703ccb5e3c7652c4398be12f50759c3d15af473b05d203b71f0383c0","control_id":"FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"6a9e72dc4e8502ab8b1877f610df0dcd54ae3529ea23748715008edfda0135d4","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"1/90/7","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"aging-fields","parameter_kind":"local-account-password-aging","parameter_locator":"/etc/shadow","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"b1ccadcb57aa2db8a2f84d67b8b4cb202ccafe8834efe5a9120c52f2ca43b580","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS') printf '%s\n' '{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"8bde26edc3fcd532874c5be570cf4e3339749ab68375453723ce991d73d9bdaa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"90","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_MAX_DAYS","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS') printf '%s\n' '{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"704c704d3c84c58f5cfb5dcc5372d87db66a7a4fa8f0051643a08a4cbf8ab9a5","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_MIN_DAYS","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE') printf '%s\n' '{"adapter_contract_sha256":"b8ba4d7a9751edeb8302e8970d688dc5f9654a1a5b28f7f9ccef284b282ac414","adapter_id":"product-login-defs-option-check-v1","adapter_implementation_sha256":"707090ed83ae29fc46bca5ddf6357ad80adec47f65cb79a7012d360479381499","control_id":"FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"74d7bae596945e5654deec69c6fbd7945fce969b55fde431e02e8d9730b99bb5","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"7","index_id":"SRC-0055","layer":"fstec-core","parameter_key":"PASS_WARN_AGE","parameter_kind":"login-defs-option","parameter_locator":"/etc/login.defs","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"11290ba6538c908723ba37166746596f20be786c606520fabfd7fde879586499","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"67cbaaa9df5e98fcd12c96ba92d02e957efa22074ccb33a3820db7f13f73afbe","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"dcredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"1aff5be225b04b25fc448d994428c5d0c081120ab56d2e0834576dea6d5e7982","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"enforce_for_root","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"8832241ba830a475148e27c3e437a5462face59f7256193684bfa1e6d4db5086","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"lcredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f33c9b1a8a94c4c8b52c67c10cc606c4c039cac9cf0e3ed28d36984258c8b5ec","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"ge","expected_type":"integer","expected_value":12,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"minlen","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b74080352b7d7530f3cedc2792d179567a299ef2c2625d0e3d55da88b6aa04d","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ocredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b92fa23522ea192c73d823fba595c11a493122883c116c53cc900c1cff02b11","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"retry","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT') printf '%s\n' '{"adapter_contract_sha256":"d229bd4e935092f2201ea5613eab10e55f12859c921c0285f0b4360f47c4cf95","adapter_id":"product-pam-pwquality-option-check-v1","adapter_implementation_sha256":"f99e93e4b8623b05d87b84a735cf3c1c3e50fdd3157b94afe6aadb9931915b0f","control_id":"FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"e422ad1e82c1d3bb471800da1820dccc8e28ba4cfc0811aa038cfffa7f341154","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":-1,"index_id":"SRC-0055","layer":"fstec-core","parameter_key":"ucredit","parameter_kind":"pam-pwquality-option","parameter_locator":"/etc/pam.d/common-password|/etc/security/pwquality.conf","product_status":"RELEASE","quote_sha256":"5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"74938cfbc4416cc217f75c6e6fe23c059833a51a1e476910207d2d93cc5ac187","source_locator":"1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT') printf '%s\n' '{"adapter_contract_sha256":"be4c65241b45bf9b9695d078f1febb54f849ee6461dfc6b18a900dfb96cc5cd4","adapter_id":"product-pam-pwhistory-remember-check-v1","adapter_implementation_sha256":"60f82120ba7786fe9f156ab5cedee420f82f2576324d7c5924f23fafb663c4fd","control_id":"FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"fb81ed55cf5d47444ef18819fd9af29599c0878e6496b1f864d221096829a743","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0056","layer":"fstec-core","parameter_key":"enforce_for_root","parameter_kind":"pam-pwhistory-remember","parameter_locator":"/etc/pam.d/common-password","product_status":"RELEASE","quote_sha256":"d7fc2ec1e041a96c320f1355a99ddd18b8110bb98355e7579da29c09aa3b623d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"3c41ce785fe6d1fb873cb32c6cda1954f2f28f384ef5175a8bcfea6d6e19bd60","source_locator":"1.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER') printf '%s\n' '{"adapter_contract_sha256":"be4c65241b45bf9b9695d078f1febb54f849ee6461dfc6b18a900dfb96cc5cd4","adapter_id":"product-pam-pwhistory-remember-check-v1","adapter_implementation_sha256":"60f82120ba7786fe9f156ab5cedee420f82f2576324d7c5924f23fafb663c4fd","control_id":"FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"b91bc68c49dc3fd272b0cd9bb048e6a08be3c00eaf54549303536be12a1eab81","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"ge","expected_type":"integer","expected_value":5,"index_id":"SRC-0056","layer":"fstec-core","parameter_key":"remember","parameter_kind":"pam-pwhistory-remember","parameter_locator":"/etc/pam.d/common-password","product_status":"RELEASE","quote_sha256":"d7fc2ec1e041a96c320f1355a99ddd18b8110bb98355e7579da29c09aa3b623d","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"3c41ce785fe6d1fb873cb32c6cda1954f2f28f384ef5175a8bcfea6d6e19bd60","source_locator":"1.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL') printf '%s\n' '{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"5b24302f05d5e939a14c799b3a6a6ebb9cf95cd4d360aef68be75b658ec3eb6b","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"VERBOSE","index_id":"SRC-0091","layer":"fstec-core","parameter_key":"LogLevel","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"a40740a4d2f728fd1f16a2e48ceb6c2ee8a49ec3eefa633d17b13af7863411c6","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"8.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION') printf '%s\n' '{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"76f8526661cb3c9854c2e8436d98649482a2be5a6bc4e7b953ac97db71a5a5aa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PasswordAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS') printf '%s\n' '{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"eb6ea9f476a6b65ef758631f9a920e5c9af3d1f7b136145f2727991641c88055","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PermitEmptyPasswords","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"ff7f9436907ec698f6298a7d3a5a785da36399228a0f213295ec0626303c8cd2","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"fstec-core","parameter_key":"PermitRootLogin","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION') printf '%s\n' '{"adapter_contract_sha256":"4540543a7bf30ca6cd558f3d62b64509624ff809283a40a3eb2ba07f7372149b","adapter_id":"product-sshd-config-option-check-v2","adapter_implementation_sha256":"b982594f06a058997a220f7c7f8fc6795515f05fd583a83e03b8c9b0459a8be4","control_id":"RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"f6a5107dbd68d885e0ea4fc526a4525b4c19fdb02a69da1bbc302c061e3072c8","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","layer":"recommended","parameter_key":"KbdInteractiveAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"RELEASE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"8425b468c13c2b05698300b93ce5597c5933c238393fe45f58194082538c98b2","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-11.2-FTP') printf '%s\n' '{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-FTP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"4e1b1a63aabb01c3ee3281d8d07dab5c6e39353ade2ddbaead0b8c1dbc7963a1","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"ftp","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-11.2-SNMP') printf '%s\n' '{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-SNMP","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"c892a0edd6da6fa55ee77205d5f10f08fe5e7152a960bd92b2ddde100e6c00b0","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"snmp","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-11.2-TELNET') printf '%s\n' '{"adapter_contract_sha256":"de75293fcabda2f71617bb8db49360a44a8318066d02b51a7a8489a25a3d65ae","adapter_id":"product-network-service-disabled-check-v1","adapter_implementation_sha256":"79d7a8b326b852cc98856cd0d7feb6e05abfdfe2e8f58f561d213f01d832f71b","control_id":"FSTEC-CONFIGURATION-2026-11.2-TELNET","control_manifest_sha256":"5a9728f758217398eb6ad19dacef60f1b80dd4a0bc8b66724da867421675da39","control_sha256":"9b84a63eb9852a42dd1b692e72062137d23e83c817b6d5d1e72db24d26f35ec8","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"disabled","index_id":"SRC-0098","layer":"fstec-core","parameter_key":"telnet","parameter_kind":"network-service-disabled","parameter_locator":"systemd|/proc/net","product_status":"RELEASE","quote_sha256":"758cb1f1a0b030c2b5bad0fff2cf790b7462faede141c9a1c59fd808187d73f0","registry_sha256":"c76609b75c423847f3633df159e1f29486be57f83e0461ef87bc966d11ddb6a8","semantic_contract_sha256":"52ee2c1d20d3203d1063596a9937b0175b07f5a03673b8278743b3b0e72e8abf","source_locator":"11.2","target_id":"linux-x86_64-supported-v1"}' ;;
    *) return 2 ;;
  esac || return 1
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=RELEASE' \
    'PRODUCT=SecureLinux-Audit' \
    'VARIANT=check-only' \
    'VERSION=1.0.9' \
    'CONTROL_COUNT=86' \
    'CONTROL_COUNT_FSTEC_CORE=85' \
    'CONTROL_COUNT_RECOMMENDED=1' \
    'TARGET_FAMILY_ID=linux-x86_64-supported-v1' \
    'SUPPORTED_ENVIRONMENTS=7'
}

slp_help() {
  command /usr/bin/cat <<'SLP_HELP_EOF'
SecureLinux-Audit: check-only CLI (только проверка, изменений не выполняет)

Использование:
  ./securelinux-audit.sh --check [--failed] [--format pretty|raw|json|pdf] [--layer L]
  ./securelinux-audit.sh --build-info
  ./securelinux-audit.sh --list
  ./securelinux-audit.sh --provenance [CONTROL_ID]
  ./securelinux-audit.sh --version
  ./securelinux-audit.sh --help

Режимы:
  --check               read-only проверка текущих canonical controls слоя
  --layer L             набор контролей: fstec-core (по умолчанию) или recommended;
                        допускается только с --check
  --check --failed      показать только FAIL и ERROR
  --format pretty       выровненная таблица для пользователя (по умолчанию)
  --format raw          стабильный SLP-CHECK-V1 TSV для автоматизации
  --format json         структурированный JSON-отчёт
  --format pdf          отчёт PDF (stdout: байты PDF, только ASCII)
  --build-info          metadata сборки
  --list                id, source, control и layer всех controls
  --provenance          provenance всех controls или одного CONTROL_ID
  --version             версия product CLI

Без аргументов печатается эта справка. Файл содержит только код проверки:
код изменения состояния хоста отсутствует физически.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Audit' \
    'PRODUCT_CLI=product-cli-v1' \
    'VARIANT=check-only' \
    'STATUS=RELEASE' \
    'VERSION=1.0.9' \
    'CONTROL_COUNT=86' \
    'TARGET_FAMILY_ID=linux-x86_64-supported-v1'
}

slp_json_escape() {
  local _slp_s=$1
  _slp_s=${_slp_s//\\/\\\\}
  _slp_s=${_slp_s//\"/\\\"}
  _slp_s=${_slp_s//$'\x01'/\\u0001}
  _slp_s=${_slp_s//$'\x02'/\\u0002}
  _slp_s=${_slp_s//$'\x03'/\\u0003}
  _slp_s=${_slp_s//$'\x04'/\\u0004}
  _slp_s=${_slp_s//$'\x05'/\\u0005}
  _slp_s=${_slp_s//$'\x06'/\\u0006}
  _slp_s=${_slp_s//$'\x07'/\\u0007}
  _slp_s=${_slp_s//$'\x08'/\\b}
  _slp_s=${_slp_s//$'\t'/\\t}
  _slp_s=${_slp_s//$'\n'/\\n}
  _slp_s=${_slp_s//$'\x0b'/\\u000b}
  _slp_s=${_slp_s//$'\x0c'/\\f}
  _slp_s=${_slp_s//$'\r'/\\r}
  _slp_s=${_slp_s//$'\x0e'/\\u000e}
  _slp_s=${_slp_s//$'\x0f'/\\u000f}
  _slp_s=${_slp_s//$'\x10'/\\u0010}
  _slp_s=${_slp_s//$'\x11'/\\u0011}
  _slp_s=${_slp_s//$'\x12'/\\u0012}
  _slp_s=${_slp_s//$'\x13'/\\u0013}
  _slp_s=${_slp_s//$'\x14'/\\u0014}
  _slp_s=${_slp_s//$'\x15'/\\u0015}
  _slp_s=${_slp_s//$'\x16'/\\u0016}
  _slp_s=${_slp_s//$'\x17'/\\u0017}
  _slp_s=${_slp_s//$'\x18'/\\u0018}
  _slp_s=${_slp_s//$'\x19'/\\u0019}
  _slp_s=${_slp_s//$'\x1a'/\\u001a}
  _slp_s=${_slp_s//$'\x1b'/\\u001b}
  _slp_s=${_slp_s//$'\x1c'/\\u001c}
  _slp_s=${_slp_s//$'\x1d'/\\u001d}
  _slp_s=${_slp_s//$'\x1e'/\\u001e}
  _slp_s=${_slp_s//$'\x1f'/\\u001f}
  printf '%s' "$_slp_s"
}

slp_presentation_for_control() {
  local _slp_cid=$1
  case "$_slp_cid" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s' 'fstec-linux-2022 §2.1.1	local-account-password-state	all non-empty' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s' 'fstec-linux-2022 §2.1.2	ssh-root-login	= no' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s' 'fstec-linux-2022 §2.2.1	su-wheel-access	rule and root in wheel: auth required pam_wheel.so use_uid;wheel:root' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s' 'fstec-linux-2022 §2.2.2	sudoers-reviewed-policy	stock rules only: root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s' 'fstec-linux-2022 §2.3.1	group-mode	= 0644' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s' 'fstec-linux-2022 §2.3.1	passwd-mode	= 0644' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s' 'fstec-linux-2022 §2.3.1	shadow-go-rwx	= 0640' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.2	running-process-paths-write-protection	runtime paths safe' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.3	cron-command-paths-write-protection	cron command paths safe' ;;
    'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.4	sudo-root-command-files-protection	owner root if regular user; go-w if other-writable' ;;
    'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.5	startup-files-write-protection	bits 0002 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s' 'fstec-linux-2022 §2.3.6	cron-d	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-daily	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-hourly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-monthly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-weekly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s' 'fstec-linux-2022 §2.3.6	crontab	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s' 'fstec-linux-2022 §2.3.7	user-cron-files-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s' 'fstec-linux-2022 §2.3.8	standard-system-paths-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s' 'fstec-linux-2022 §2.3.9	suid-sgid-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s' 'fstec-linux-2022 §2.3.10	home-sensitive-files-mode	bits 0077 = 0' ;;
    'FSTEC-LINUX-2022-2.3.11-DIR-MODE') printf '%s' 'fstec-linux-2022 §2.3.11	dir-mode	= 0700' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s' 'fstec-linux-2022 §2.3.11	home-directories-mode	= 0700' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-MODE') printf '%s' 'fstec-linux-2022 §2.3.11	home-mode	= 0700' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s' 'fstec-linux-2022 §2.4.1	dmesg-restrict	= 1' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s' 'fstec-linux-2022 §2.4.2	kptr-restrict	= 2' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s' 'fstec-linux-2022 §2.4.3	init-on-alloc	= 1' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s' 'fstec-linux-2022 §2.4.4	slab-nomerge	present' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-force	= force' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-passthrough	= 0' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-strict	= 1' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s' 'fstec-linux-2022 §2.4.6	randomize-kstack-offset	= 1' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s' 'fstec-linux-2022 §2.4.7	mitigations	= auto,nosmt' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s' 'fstec-linux-2022 §2.4.8	bpf-jit-harden	= 2' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s' 'fstec-linux-2022 §2.5.1	vsyscall	= none' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s' 'fstec-linux-2022 §2.5.2	perf-event-paranoid	= 3' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s' 'fstec-linux-2022 §2.5.3	debugfs	one of: off|no-mount' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s' 'fstec-linux-2022 §2.5.4	kexec-load-disabled	= 1' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s' 'fstec-linux-2022 §2.5.5	max-user-namespaces	= 0' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s' 'fstec-linux-2022 §2.5.6	unprivileged-bpf-disabled	= 1' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s' 'fstec-linux-2022 §2.5.7	unprivileged-userfaultfd	= 0' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s' 'fstec-linux-2022 §2.5.8	ldisc-autoload	= 0' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s' 'fstec-linux-2022 §2.5.9	tsx	= off' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s' 'fstec-linux-2022 §2.5.10	mmap-min-addr	>= 4096' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s' 'fstec-linux-2022 §2.5.11	randomize-va-space	= 2' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s' 'fstec-linux-2022 §2.6.1	ptrace-scope	= 3' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s' 'fstec-linux-2022 §2.6.2	protected-symlinks	= 1' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s' 'fstec-linux-2022 §2.6.3	protected-hardlinks	= 1' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s' 'fstec-linux-2022 §2.6.4	protected-fifos	= 2' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s' 'fstec-linux-2022 §2.6.5	protected-regular	= 2' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s' 'fstec-linux-2022 §2.6.6	suid-dumpable	= 0' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE') printf '%s' 'fstec-logging-2025 §app2:1	auditd-package	= installed' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE') printf '%s' 'fstec-logging-2025 §app2:2	auditd-service	= enabled-active' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION') printf '%s' 'fstec-logging-2025 §app2:3	admin-space-left-action	= suspend' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION') printf '%s' 'fstec-logging-2025 §app2:3	disk-full-action	= suspend' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE') printf '%s' 'fstec-logging-2025 §app2:3	log-file	= /var/log/audit/audit.log' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT') printf '%s' 'fstec-logging-2025 §app2:3	log-format	= ENRICHED' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP') printf '%s' 'fstec-logging-2025 §app2:3	log-group	= root' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE') printf '%s' 'fstec-logging-2025 §app2:3	max-log-file	= 50' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION') printf '%s' 'fstec-logging-2025 §app2:3	max-log-file-action	= rotate' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS') printf '%s' 'fstec-logging-2025 §app2:3	num-logs	= 150' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION') printf '%s' 'fstec-logging-2025 §app2:3	space-left-action	= syslog' ;;
    'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES') printf '%s' 'fstec-logging-2025 §app2:4	audit-rules	= present' ;;
    'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE') printf '%s' 'fstec-logging-2025 §main:5	audit-log-free-space	>= 7516192768' ;;
    'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD') printf '%s' 'fstec-configuration-2026 §1.1	encrypt-method	one of: SHA512|YESCRYPT' ;;
    'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING') printf '%s' 'fstec-configuration-2026 §1.1	existing-password-aging	= 1/90/7' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS') printf '%s' 'fstec-configuration-2026 §1.1	pass-max-days	= 90' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS') printf '%s' 'fstec-configuration-2026 §1.1	pass-min-days	= 1' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE') printf '%s' 'fstec-configuration-2026 §1.1	pass-warn-age	= 7' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-dcredit	= -1' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-enforce-for-root	= 1' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-lcredit	= -1' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-minlen	>= 12' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-ocredit	= -1' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-retry	= 3' ;;
    'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT') printf '%s' 'fstec-configuration-2026 §1.1	pwquality-ucredit	= -1' ;;
    'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT') printf '%s' 'fstec-configuration-2026 §1.2	pwhistory-enforce-for-root	= 1' ;;
    'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER') printf '%s' 'fstec-configuration-2026 §1.2	pwhistory-remember	>= 5' ;;
    'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL') printf '%s' 'fstec-configuration-2026 §8.4	ssh-log-level	= VERBOSE' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION') printf '%s' 'fstec-configuration-2026 §9.1	ssh-password-authentication	= no' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS') printf '%s' 'fstec-configuration-2026 §9.1	ssh-permit-empty-passwords	= no' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN') printf '%s' 'fstec-configuration-2026 §9.1	ssh-permit-root-login	= no' ;;
    'RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION') printf '%s' 'fstec-configuration-2026 §9.1	recommended-configuration-2026-9.1-ssh-kbd-interactive-authentication	= no' ;;
    'FSTEC-CONFIGURATION-2026-11.2-FTP') printf '%s' 'fstec-configuration-2026 §11.2	ftp	= disabled' ;;
    'FSTEC-CONFIGURATION-2026-11.2-SNMP') printf '%s' 'fstec-configuration-2026 §11.2	snmp	= disabled' ;;
    'FSTEC-CONFIGURATION-2026-11.2-TELNET') printf '%s' 'fstec-configuration-2026 §11.2	telnet	= disabled' ;;
    *) return 1 ;;
  esac
}

slp_pretty_status() {
  case "$1" in
    PASS) printf '%s' ok ;;
    FAIL) printf '%s' fail ;;
    ERROR) printf '%s' err ;;
    NOT_FOUND) printf '%s' nf ;;
    NOT_APPLICABLE) printf '%s' na ;;
    *) return 1 ;;
  esac
}

SLP_PRETTY_COLS=116
SLP_PRETTY_MODE=table
# Терминал ли stdout для раскладки pretty: 1 или 0 задаёт slp_run_check на время своего вызова (local;
# вывод собирается до записи), пусто: по текущему stdout.
SLP_STDOUT_TTY=''
# Управляющие символы C0 (кроме NUL: его в строке bash нет), DEL и C1 (U+0080–U+009F, байты UTF-8
# C2 80–C2 9F): для замены на «?» в выводе терминала; таблица задана байтами и не зависит от локали.
SLP_TERMINAL_CONTROLS=()
for _slp_i in {1..31} 127; do
  printf -v _slp_hex '%02x' "$_slp_i"
  printf -v _slp_c "\\x$_slp_hex"
  SLP_TERMINAL_CONTROLS+=("$_slp_c")
done
for _slp_i in {128..159}; do
  printf -v _slp_hex '%02x' "$_slp_i"
  printf -v _slp_c "\\xc2\\x$_slp_hex"
  SLP_TERMINAL_CONTROLS+=("$_slp_c")
done
unset _slp_i _slp_hex _slp_c

slp_terminal_text() {
  # Замена управляющих символов на «?»; результат: SLP_TERMINAL_TEXT. В корректном
  # UTF-8 байты C2 80–C2 9F встречаются только как символы U+0080–U+009F.
  local _slp_text=$1 _slp_c
  for _slp_c in "${SLP_TERMINAL_CONTROLS[@]}"; do
    _slp_text=${_slp_text//"$_slp_c"/?}
  done
  SLP_TERMINAL_TEXT=$_slp_text
}
# Значения для 116 колонок; slp_pretty_layout_init пересчитывает их до печати.
SLP_PRETTY_WS=6
SLP_PRETTY_WSRC=30
SLP_PRETTY_WC=28
SLP_PRETTY_WCUR=14
SLP_PRETTY_WREQ=22
SLP_PRETTY_VFIELD=8
SLP_PRETTY_VVALUE=101

slp_terminal_columns() {
  local _slp_size='' _slp_rows='' _slp_cols='' _slp_extra=''
  if [[ -r /dev/tty && -x /usr/bin/stty ]]; then
    _slp_size=$(command /usr/bin/stty size < /dev/tty 2>/dev/null) || _slp_size=''
    if [[ -n $_slp_size ]]; then
      read -r _slp_rows _slp_cols _slp_extra <<< "$_slp_size"
      if [[ $_slp_rows =~ ^[0-9]+$ && $_slp_cols =~ ^[0-9]+$ && -z $_slp_extra ]] && (( _slp_cols >= 40 && _slp_cols <= 1000 )); then
        printf '%s\n' "$_slp_cols" || return 1
        return 0
      fi
    fi
  fi
  printf '116\n'
}

slp_pretty_layout_for_cols() {
  local _slp_cols=$1 _slp_available _slp_remaining _slp_req_min
  [[ $_slp_cols =~ ^[0-9]+$ ]] || return 1
  (( _slp_cols >= 40 && _slp_cols <= 1000 )) || return 1
  SLP_PRETTY_COLS=$_slp_cols
  SLP_PRETTY_WS=6
  if (( _slp_cols < 90 )); then
    SLP_PRETTY_MODE=vertical
    SLP_PRETTY_VFIELD=8
    SLP_PRETTY_VVALUE=$((_slp_cols - SLP_PRETTY_VFIELD - 7))
    (( SLP_PRETTY_VVALUE > 0 )) || return 1
    return 0
  fi
  SLP_PRETTY_MODE=table
  if (( _slp_cols < 100 )); then
    SLP_PRETTY_WSRC=18
    SLP_PRETTY_WC=24
    _slp_req_min=8
  elif (( _slp_cols < 110 )); then
    SLP_PRETTY_WSRC=30
    SLP_PRETTY_WC=24
    _slp_req_min=10
  elif (( _slp_cols < 120 )); then
    SLP_PRETTY_WSRC=30
    SLP_PRETTY_WC=28
    _slp_req_min=12
  else
    SLP_PRETTY_WSRC=30
    SLP_PRETTY_WC=32
    _slp_req_min=14
  fi
  _slp_available=$((_slp_cols - 16))
  _slp_remaining=$((_slp_available - SLP_PRETTY_WS - SLP_PRETTY_WSRC - SLP_PRETTY_WC))
  (( _slp_remaining > _slp_req_min )) || return 1
  SLP_PRETTY_WCUR=$((_slp_remaining - _slp_req_min))
  (( SLP_PRETTY_WCUR > 43 )) && SLP_PRETTY_WCUR=43
  # current отдаёт required 10 символов, но не становится уже 12.
  if (( SLP_PRETTY_WCUR - 10 > 12 )); then
    SLP_PRETTY_WCUR=$((SLP_PRETTY_WCUR - 10))
  elif (( SLP_PRETTY_WCUR > 12 )); then
    SLP_PRETTY_WCUR=12
  fi
  SLP_PRETTY_WREQ=$((_slp_remaining - SLP_PRETTY_WCUR))
}

slp_pretty_layout_init() {
  local _slp_cols _slp_tty=$SLP_STDOUT_TTY
  if [[ -z $_slp_tty ]]; then
    _slp_tty=0
    if [[ -t 1 ]]; then
      _slp_tty=1
    fi
  fi
  if [[ $_slp_tty != 1 ]]; then
    slp_pretty_layout_for_cols 116
    return $?
  fi
  _slp_cols=$(slp_terminal_columns) || return 1
  slp_pretty_layout_for_cols "$_slp_cols"
}

slp_repeat_dash() {
  local _slp_n=$1 _slp_out
  printf -v _slp_out '%*s' "$_slp_n" ''
  printf '%s' "${_slp_out// /-}"
}

slp_pretty_separator() {
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    printf '+' || return 1
    slp_repeat_dash $((SLP_PRETTY_VFIELD + 2)) || return 1
    printf '+' || return 1
    slp_repeat_dash $((SLP_PRETTY_VVALUE + 2)) || return 1
    printf '+\n' || return 1
    return 0
  fi
  printf '+' || return 1
  slp_repeat_dash $((SLP_PRETTY_WS + 2)) || return 1
  printf '+' || return 1
  slp_repeat_dash $((SLP_PRETTY_WSRC + 2)) || return 1
  printf '+' || return 1
  slp_repeat_dash $((SLP_PRETTY_WC + 2)) || return 1
  printf '+' || return 1
  slp_repeat_dash $((SLP_PRETTY_WCUR + 2)) || return 1
  printf '+' || return 1
  slp_repeat_dash $((SLP_PRETTY_WREQ + 2)) || return 1
  printf '+\n' || return 1
}

slp_pretty_cell() {
  local _slp_text=$1 _slp_width=$2 _slp_chars _slp_bytes _slp_printf_width
  local LC_ALL=C.UTF-8
  _slp_chars=${#_slp_text}
  LC_ALL=C
  _slp_bytes=${#_slp_text}
  _slp_printf_width=$((_slp_width + _slp_bytes - _slp_chars))
  printf '%-*s' "$_slp_printf_width" "$_slp_text"
}

slp_pretty_split() {
  # Делит текст по ширине: разрыв по последнему пробелу или после последнего «;» в пределах ширины,
  # иначе после последнего «-» или «:», иначе по ширине (та же логика, что _split_chunk в dispatcher).
  # Результат: SLP_SPLIT_HEAD и SLP_SPLIT_REST.
  local LC_ALL=C.UTF-8
  local _slp_text=$1 _slp_width=$2 _slp_win _slp_pre _slp_space=-1 _slp_semi=-1 _slp_cut
  if (( ${#_slp_text} <= _slp_width )); then
    SLP_SPLIT_HEAD=$_slp_text
    SLP_SPLIT_REST=''
    return 0
  fi
  _slp_win=${_slp_text:0:_slp_width+1}
  if [[ $_slp_win == *' '* ]]; then
    _slp_pre=${_slp_win% *}
    _slp_space=${#_slp_pre}
  fi
  _slp_win=${_slp_text:0:_slp_width}
  if [[ $_slp_win == *';'* ]]; then
    _slp_pre=${_slp_win%;*}
    _slp_semi=$(( ${#_slp_pre} + 1 ))
  fi
  _slp_cut=$_slp_space
  if (( _slp_semi > _slp_cut )); then
    _slp_cut=$_slp_semi
  fi
  if (( _slp_cut * 3 < _slp_width )); then
    _slp_cut=0
    if [[ $_slp_win == *[-:]* ]]; then
      _slp_pre=${_slp_win%[-:]*}
      _slp_cut=$(( ${#_slp_pre} + 1 ))
    fi
    if (( _slp_cut * 3 < _slp_width )); then
      _slp_cut=$_slp_width
    fi
  fi
  SLP_SPLIT_HEAD=${_slp_text:0:_slp_cut}
  SLP_SPLIT_REST=${_slp_text:_slp_cut}
  SLP_SPLIT_HEAD=${SLP_SPLIT_HEAD%"${SLP_SPLIT_HEAD##*[! ]}"}
  SLP_SPLIT_REST=${SLP_SPLIT_REST#"${SLP_SPLIT_REST%%[! ]*}"}
  return 0
}

slp_pretty_vertical_field() {
  local LC_ALL=C.UTF-8
  local _slp_label=$1 _slp_text=$2 _slp_chunk
  if [[ -z $_slp_text ]]; then
    printf '|' || return 1
    printf ' ' || return 1
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD" || return 1
    printf ' | ' || return 1
    slp_pretty_cell '' "$SLP_PRETTY_VVALUE" || return 1
    printf ' |\n' || return 1
    return 0
  fi
  while [[ -n $_slp_text ]]; do
    slp_pretty_split "$_slp_text" "$SLP_PRETTY_VVALUE"
    _slp_chunk=$SLP_SPLIT_HEAD
    _slp_text=$SLP_SPLIT_REST
    printf '|' || return 1
    printf ' ' || return 1
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD" || return 1
    printf ' | ' || return 1
    slp_pretty_cell "$_slp_chunk" "$SLP_PRETTY_VVALUE" || return 1
    printf ' |\n' || return 1
    _slp_label=''
  done
}

slp_pretty_row() {
  local LC_ALL=C.UTF-8
  local _slp_st=$1 _slp_source=$2 _slp_control=$3 _slp_current=$4 _slp_required=$5
  local _slp_a _slp_b _slp_c _slp_d _slp_e
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    if [[ $_slp_st == status && $_slp_source == source && $_slp_control == control ]]; then
      printf '|' || return 1
      printf ' ' || return 1
      slp_pretty_cell field "$SLP_PRETTY_VFIELD" || return 1
      printf ' | ' || return 1
      slp_pretty_cell value "$SLP_PRETTY_VVALUE" || return 1
      printf ' |\n' || return 1
      return 0
    fi
    slp_pretty_vertical_field status "$_slp_st" || return 1
    slp_pretty_vertical_field source "$_slp_source" || return 1
    slp_pretty_vertical_field control "$_slp_control" || return 1
    slp_pretty_vertical_field current "$_slp_current" || return 1
    slp_pretty_vertical_field required "$_slp_required" || return 1
    return 0
  fi
  while [[ -n $_slp_st || -n $_slp_source || -n $_slp_control || -n $_slp_current || -n $_slp_required ]]; do
    slp_pretty_split "$_slp_st" "$SLP_PRETTY_WS"; _slp_a=$SLP_SPLIT_HEAD; _slp_st=$SLP_SPLIT_REST
    slp_pretty_split "$_slp_source" "$SLP_PRETTY_WSRC"; _slp_b=$SLP_SPLIT_HEAD; _slp_source=$SLP_SPLIT_REST
    slp_pretty_split "$_slp_control" "$SLP_PRETTY_WC"; _slp_c=$SLP_SPLIT_HEAD; _slp_control=$SLP_SPLIT_REST
    slp_pretty_split "$_slp_current" "$SLP_PRETTY_WCUR"; _slp_d=$SLP_SPLIT_HEAD; _slp_current=$SLP_SPLIT_REST
    slp_pretty_split "$_slp_required" "$SLP_PRETTY_WREQ"; _slp_e=$SLP_SPLIT_HEAD; _slp_required=$SLP_SPLIT_REST
    printf '|' || return 1
    printf ' ' || return 1
    slp_pretty_cell "$_slp_a" "$SLP_PRETTY_WS" || return 1
    printf ' | ' || return 1
    slp_pretty_cell "$_slp_b" "$SLP_PRETTY_WSRC" || return 1
    printf ' | ' || return 1
    slp_pretty_cell "$_slp_c" "$SLP_PRETTY_WC" || return 1
    printf ' | ' || return 1
    slp_pretty_cell "$_slp_d" "$SLP_PRETTY_WCUR" || return 1
    printf ' | ' || return 1
    slp_pretty_cell "$_slp_e" "$SLP_PRETTY_WREQ" || return 1
    printf ' |\n' || return 1
  done
}

slp_collect_policy() {
  # reason допускает необязательный третий сегмент-payload (путь, цель
  # readlink и т. п.): <domain>:<reason>[:<payload>]. Payload может содержать
  # любые байты, кроме control-байт (0x00-0x1F, 0x7F): они ломают
  # табличный/TSV вывод. Локаль фиксируется явно: классификация [:cntrl:]
  # обязана быть побайтовой, не зависеть от окружения вызова.
  # Аргументы: control id: проверяются только они.
  local LC_ALL=C
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i _slp_want _slp_bad _slp_record_errors=0 _slp_rest
  if [[ ${1:-} == --record-errors ]]; then
    _slp_record_errors=1
    shift
  fi
  local -a _slp_fns=('slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE' 'slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN' 'slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS' 'slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY' 'slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX' 'slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_4_SUDO_ROOT_COMMAND_FILES_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_5_STARTUP_FILES_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB' 'slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_DIR_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_MODE' 'slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC' 'slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT' 'slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET' 'slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS' 'slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN' 'slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL' 'slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID' 'slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS' 'slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES' 'slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD' 'slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD' 'slp_check_FSTEC_LINUX_2022_2_5_9_TSX' 'slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE' 'slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE' 'slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS' 'slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR' 'slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_1_AUDITD_PACKAGE' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_2_AUDITD_SERVICE' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_ADMIN_SPACE_LEFT_ACTION' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_DISK_FULL_ACTION' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_FILE' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_FORMAT' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_LOG_GROUP' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_MAX_LOG_FILE' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_MAX_LOG_FILE_ACTION' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_NUM_LOGS' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_3_SPACE_LEFT_ACTION' 'slp_check_FSTEC_LOGGING_2025_APPENDIX2_LINUX_4_AUDIT_RULES' 'slp_check_FSTEC_LOGGING_2025_MAIN_5_AUDIT_LOG_FREE_SPACE' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_ENCRYPT_METHOD' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_EXISTING_PASSWORD_AGING' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_MAX_DAYS' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_MIN_DAYS' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PASS_WARN_AGE' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_DCREDIT' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_ENFORCE_FOR_ROOT' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_LCREDIT' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_MINLEN' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_OCREDIT' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_RETRY' 'slp_check_FSTEC_CONFIGURATION_2026_1_1_PWQUALITY_UCREDIT' 'slp_check_FSTEC_CONFIGURATION_2026_1_2_PWHISTORY_ENFORCE_FOR_ROOT' 'slp_check_FSTEC_CONFIGURATION_2026_1_2_PWHISTORY_REMEMBER' 'slp_check_FSTEC_CONFIGURATION_2026_8_4_SSH_LOG_LEVEL' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PASSWORD_AUTHENTICATION' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_EMPTY_PASSWORDS' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_ROOT_LOGIN' 'slp_check_FSTEC_CONFIGURATION_2026_11_2_FTP' 'slp_check_FSTEC_CONFIGURATION_2026_11_2_SNMP' 'slp_check_FSTEC_CONFIGURATION_2026_11_2_TELNET')
  local -a _slp_ids=('FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' 'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS' 'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.6-CRON-D' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' 'FSTEC-LINUX-2022-2.3.11-DIR-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-MODE' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' 'FSTEC-LINUX-2022-2.5.9-TSX' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION' 'FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES' 'FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE' 'FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD' 'FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS' 'FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS' 'FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY' 'FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT' 'FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER' 'FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' 'FSTEC-CONFIGURATION-2026-11.2-FTP' 'FSTEC-CONFIGURATION-2026-11.2-SNMP' 'FSTEC-CONFIGURATION-2026-11.2-TELNET')
  local -a _slp_fns_rec=('slp_check_RECOMMENDED_CONFIGURATION_2026_9_1_SSH_KBD_INTERACTIVE_AUTHENTICATION')
  local -a _slp_ids_rec=('RECOMMENDED-CONFIGURATION-2026-9.1-SSH-KBD-INTERACTIVE-AUTHENTICATION')
  case "${SLP_LAYER:-fstec-core}" in
    recommended) _slp_fns=("${_slp_fns_rec[@]}"); _slp_ids=("${_slp_ids_rec[@]}") ;;
    fstec-core) ;;
    *) printf 'CHECK_INTERNAL_ERROR\n' >&2; return 1 ;;
  esac
  local -A _slp_only=()
  for _slp_want in "$@"; do _slp_only[$_slp_want]=1; done

  SLP_RESULTS=()
  SLP_TOTAL=0 SLP_PASS=0 SLP_FAIL=0 SLP_NF=0 SLP_NA=0 SLP_ERR=0 SLP_POLICY_STATUS='' SLP_POLICY_RC=0

  for ((_slp_i=0; _slp_i<${#_slp_fns[@]}; _slp_i++)); do
    _slp_fn=${_slp_fns[$_slp_i]}
    _slp_expected_cid=${_slp_ids[$_slp_i]}
    if (( $# > 0 )) && [[ -z ${_slp_only[$_slp_expected_cid]+x} ]]; then
      continue
    fi
    _slp_bad=0
    _slp_tag='' _slp_cid='' _slp_status='' _slp_value='' _slp_comp='' _slp_extra=''
    if ! _slp_line="$($_slp_fn)"; then
      _slp_bad=1
    else
      if [[ $_slp_line == *$'\n'* ]]; then
        _slp_bad=1
      fi
      _slp_rest=${_slp_line//$'\t'/}
      if (( ${#_slp_line} - ${#_slp_rest} != 4 )); then
        _slp_bad=1
      fi
      IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra <<< "$_slp_line"
      if [[ $_slp_tag != SLP-CHECK-V1 || $_slp_cid != "$_slp_expected_cid" || -n $_slp_extra ]]; then
        _slp_bad=1
      fi
      case "$_slp_status:$_slp_comp" in
        VALUE:PASS|VALUE:FAIL|NOT_FOUND:FAIL|NOT_FOUND:NOT_FOUND|NOT_APPLICABLE:NOT_APPLICABLE|ERROR:ERROR) ;;
        *) _slp_bad=1 ;;
      esac
      if [[ $_slp_bad == 0 && $_slp_comp == ERROR ]]; then
        if [[ ! $_slp_value =~ ^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*(:[^[:cntrl:]]*)?$ ]]; then
          _slp_bad=1
        fi
      fi
    fi
    if [[ $_slp_bad == 1 ]]; then
      if [[ $_slp_record_errors != 1 ]]; then
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
      fi
      _slp_line="SLP-CHECK-V1"$'\t'"$_slp_expected_cid"$'\t'"ERROR"$'\t'"check:internal-error"$'\t'"ERROR"
      _slp_status=ERROR _slp_value=check:internal-error _slp_comp=ERROR
    fi
    SLP_RESULTS+=("$_slp_line")
    ((SLP_TOTAL+=1))
    case "$_slp_comp" in
      PASS) ((SLP_PASS+=1)) ;;
      FAIL) ((SLP_FAIL+=1)) ;;
      NOT_FOUND) ((SLP_NF+=1)) ;;
      NOT_APPLICABLE) ((SLP_NA+=1)) ;;
      ERROR) ((SLP_ERR+=1)) ;;
      *) return 1 ;;
    esac
  done

  if (( $# > 0 && SLP_TOTAL != ${#_slp_only[@]} )); then
    printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
    return 1
  fi
  if (( SLP_NF > 0 || SLP_ERR > 0 )); then
    SLP_POLICY_STATUS=UNEVALUATED
    SLP_POLICY_RC=1
  elif (( SLP_FAIL > 0 )); then
    SLP_POLICY_STATUS=NONCOMPLIANT
    SLP_POLICY_RC=0
  else
    SLP_POLICY_STATUS=COMPLIANT
    SLP_POLICY_RC=0
  fi
  return 0
}

slp_selected() {
  local _slp_result=$1 _slp_failed_only=$2
  if (( _slp_failed_only == 0 )); then return 0; fi
  [[ $_slp_result == FAIL || $_slp_result == ERROR ]]
}

slp_support_class() {
  case "$SLP_SYSTEM_ENVIRONMENT" in
    'ubuntu-22.04-x86_64-full'|'ubuntu-24.04-x86_64-minimized'|'ubuntu-24.04-x86_64-full'|'ubuntu-26.04-x86_64-minimized'|'ubuntu-26.04-x86_64-full'|'debian-12-x86_64-server'|'debian-13-x86_64-server')
      printf '%s' SUPPORTED ;;
    *)
      printf '%s' UNSUPPORTED ;;
  esac
}

slp_print_system_header() {
  # Строки SUPPORT, SYSTEM, PLATFORM и TYPE/PROFILE заголовка --check ($1: класс поддержки). Значения из системы (PRETTY_NAME из /etc/os-release и др.): с заменой управляющих
  # символов на «?», как значения таблицы; каждая запись проверяется.
  local _slp_system _slp_arch _slp_platform _slp_kind=PROFILE _slp_value=$SLP_SYSTEM_PROFILE
  if [[ -n $SLP_SYSTEM_TYPE ]]; then
    _slp_kind=TYPE _slp_value=$SLP_SYSTEM_TYPE
  fi
  [[ -n $_slp_value ]] || _slp_value=UNKNOWN
  slp_terminal_text "$SLP_SYSTEM_PRETTY_NAME"; _slp_system=$SLP_TERMINAL_TEXT
  slp_terminal_text "$SLP_SYSTEM_ARCH"; _slp_arch=$SLP_TERMINAL_TEXT
  slp_terminal_text "$SLP_SYSTEM_PLATFORM"; _slp_platform=$SLP_TERMINAL_TEXT
  slp_terminal_text "$_slp_value"; _slp_value=$SLP_TERMINAL_TEXT
  printf 'SUPPORT=%s\n' "$1" || return 1
  printf 'SYSTEM=%s ARCH=%s\n' "$_slp_system" "$_slp_arch" || return 1
  printf 'PLATFORM=%s\n' "$_slp_platform" || return 1
  printf '%s=%s\n\n' "$_slp_kind" "$_slp_value" || return 1
}

slp_emit_output() {
  # Вывод команды "$@" собирается целиком и пишется одной командой, как вывод --check: сбой записи, в том
  # числе канал с закрытым читателем,: код 1 (а не 0 или завершение по SIGPIPE); ненулевой код команды
  # передаётся без вывода; сбой записи завершающей точки: код 1 при любом коде printf.
  local _slp_out _slp_rc
  _slp_out=$(
    "$@" || exit "$?"
    printf '.' || exit 1
  )
  _slp_rc=$?
  (( _slp_rc == 0 )) || return "$_slp_rc"
  [[ $_slp_out == *. ]] || return 1
  ( trap '' PIPE; printf '%s' "${_slp_out%.}" ) || return 1
}

slp_render_raw() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_support
  # Каждая запись и подстановка значения проверяется: сбой любой из них: код 1.
  _slp_support=$(slp_support_class) || return 1
  printf 'SLP-PLATFORM-V1\tSYSTEM=%s\tID=%s\tVERSION_ID=%s\tARCH=%s\tPROFILE=%s\tTYPE=%s\tPLATFORM=%s\tENVIRONMENT=%s\tSUPPORT=%s\n' \
    "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ID" "$SLP_SYSTEM_VERSION_ID" "$SLP_SYSTEM_ARCH" \
    "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT" "$_slp_support" || return 1
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    printf '%s\n' "$_slp_line" || return 1
  done
  printf 'SLP-SUMMARY-V1\tTOTAL=%d\tPASS=%d\tFAIL=%d\tNOT_FOUND=%d\tNOT_APPLICABLE=%d\tERROR=%d\tPOLICY_STATUS=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS" || return 1
}

slp_render_pretty() {
  local _slp_failed_only=$1 _slp_title=$2 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  local _slp_current _slp_required _slp_meta _slp_source _slp_control _slp_extra _slp_st _slp_support
  # Каждая запись и подстановка значения проверяется: сбой любой из них: код 1.
  _slp_support=$(slp_support_class) || return 1
  if [[ ${SLP_LAYER:-fstec-core} == fstec-core ]]; then
    printf '=== SecureLinux Audit 1.0.9: %s ===\n' "$_slp_title" || return 1
  else
    printf '=== SecureLinux Audit 1.0.9: %s (layer: %s) ===\n' "$_slp_title" "${SLP_LAYER:-}" || return 1
  fi
  slp_print_system_header "$_slp_support" || return 1
  slp_pretty_layout_init || return 1
  slp_pretty_separator || return 1
  slp_pretty_row 'status' 'source' 'control' 'current' 'required' || return 1
  slp_pretty_separator || return 1
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    if ! _slp_meta=$(slp_presentation_for_control "$_slp_cid"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    IFS=$'\t' read -r _slp_source _slp_control _slp_required _slp_extra <<< "$_slp_meta"
    if [[ -z $_slp_source || -z $_slp_control || -z $_slp_required || -n $_slp_extra ]]; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    if ! _slp_st=$(slp_pretty_status "$_slp_comp"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    case "$_slp_status" in
      VALUE) _slp_current=$_slp_value ;;
      NOT_FOUND) _slp_current='<absent>' ;;
      NOT_APPLICABLE) _slp_current='<not-applicable>' ;;
      ERROR) _slp_current="not-determined; reason: $_slp_value" ;;
      *) printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2; return 1 ;;
    esac
    # Значение CHECK: из системы: управляющие символы в терминал не выводятся (raw и json: без замены).
    slp_terminal_text "$_slp_current"
    _slp_current=$SLP_TERMINAL_TEXT
    slp_pretty_row "$_slp_st" "$_slp_source" "$_slp_control" "$_slp_current" "$_slp_required" || return 1
  done
  slp_pretty_separator || return 1
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   NOT_APPLICABLE=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS" || return 1
  case "$SLP_POLICY_STATUS" in
    UNEVALUATED)
      if (( _slp_failed_only != 0 && SLP_NF > 0 )); then
        printf '%s\n' 'POLICY=UNEVALUATED: есть ERROR или NOT_FOUND, поэтому итог не подведён; строки NOT_FOUND ключ --failed не показывает; полный список: --check без --failed.' || return 1
      else
        printf '%s\n' 'POLICY=UNEVALUATED: есть ERROR или NOT_FOUND, поэтому итог не подведён; причины в строках выше.' || return 1
      fi ;;
    NONCOMPLIANT) printf '%s\n' 'POLICY=NONCOMPLIANT: есть FAIL; ERROR и NOT_FOUND нет.' || return 1 ;;
    COMPLIANT) printf '%s\n' 'POLICY=COMPLIANT: нет FAIL, ERROR и NOT_FOUND.' || return 1 ;;
  esac
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  local _slp_support _slp_j_system _slp_j_id _slp_j_version _slp_j_arch _slp_j_profile _slp_j_type _slp_j_platform
  local _slp_j_environment _slp_j_support _slp_j_cid _slp_j_status _slp_j_value _slp_j_comp
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  # Каждая запись и подстановка значения проверяется: сбой любой из них: код 1.
  _slp_support=$(slp_support_class) || return 1
  _slp_j_system=$(slp_json_escape "$SLP_SYSTEM_PRETTY_NAME") || return 1
  _slp_j_id=$(slp_json_escape "$SLP_SYSTEM_ID") || return 1
  _slp_j_version=$(slp_json_escape "$SLP_SYSTEM_VERSION_ID") || return 1
  _slp_j_arch=$(slp_json_escape "$SLP_SYSTEM_ARCH") || return 1
  _slp_j_profile=$(slp_json_escape "$SLP_SYSTEM_PROFILE") || return 1
  _slp_j_type=$(slp_json_escape "$SLP_SYSTEM_TYPE") || return 1
  _slp_j_platform=$(slp_json_escape "$SLP_SYSTEM_PLATFORM") || return 1
  _slp_j_environment=$(slp_json_escape "$SLP_SYSTEM_ENVIRONMENT") || return 1
  _slp_j_support=$(slp_json_escape "$_slp_support") || return 1
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","platform":{"system":"%s","id":"%s","version_id":"%s","arch":"%s","profile":"%s","type":"%s","platform_id":"%s","environment_id":"%s","support":"%s"},"policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"not_applicable":%d,"error":%d},"results":[' \
    "$_slp_filter" "$_slp_j_system" "$_slp_j_id" "$_slp_j_version" "$_slp_j_arch" \
    "$_slp_j_profile" "$_slp_j_type" "$_slp_j_platform" "$_slp_j_environment" "$_slp_j_support" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" || return 1
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    _slp_j_cid=$(slp_json_escape "$_slp_cid") || return 1
    _slp_j_status=$(slp_json_escape "$_slp_status") || return 1
    _slp_j_value=$(slp_json_escape "$_slp_value") || return 1
    _slp_j_comp=$(slp_json_escape "$_slp_comp") || return 1
    if (( _slp_first == 0 )); then printf ',' || return 1; fi
    _slp_first=0
    printf '{"control_id":"%s","observation":"%s","value":"%s","result":"%s"}' \
      "$_slp_j_cid" "$_slp_j_status" "$_slp_j_value" "$_slp_j_comp" || return 1
  done
  printf ']}\n' || return 1
}

slp_render_pdf() {
  local _slp_failed_only=$1 _slp_json
  # Отчёт собирается тем же JSON, что и --format json; PDF: только ASCII.
  _slp_json=$(slp_render_json "$_slp_failed_only") || return 1
  SLP_REPORT_JSON=$_slp_json command /usr/bin/python3 -I -S -B - <<'SLP_PDF_REPORT_PY'
# Встроенный генератор PDF для --format pdf (встраивается в securelinux-audit.sh
# правкой edit-pdf-v1.py / генератором strip-checkonly-v3.py как тело heredoc
# slp_render_pdf). Запускается на целевом хосте: python3 -I -S -B -.
# Шрифт: субсет DejaVuSans (кириллица+латиница+знаки), рецепт:
#   fontTools subset DejaVuSans.ttf --unicodes=U+0020-007E,U+00A7,U+00AB,U+00BB,
#     U+00B7,U+00D7,U+0400-045F,U+2013,U+2014,U+201C,U+201D,U+2026,U+2116
# CID=unicode-кодпойнт, GID: через CIDToGIDMap; потоки: ASCIIHex+Flate,
# поэтому весь PDF: чистый ASCII и проходит канал stdout с $(…).
# Встроенный генератор отчёта PDF (SLP-REPORT-V1 -> PDF, чистый ASCII).
# Вход: SLP_REPORT_JSON (env): тот же JSON, что у --format json.
# Выход: байты PDF в stdout: только ASCII (бинарные потоки ASCIIHexDecode+Flate).
import json, os, re, sys, time

FONT_HEX = "78dad4bc79605445f63f5acbadbbf5be655fe9ac044848081008a40d8b6c425476050386b0b880220282030149409680d0201820222044c4800c0644450920041c1d4087015750718cc8383862482aefd4ed4e0067beeff77defaff7d2a9be4bdfaee5ac9f73aaaa11460839e14d427177f7eed357b9a47c82d0f2917077e4dd0543eeb776495a00d7d50859f7df7dffb0fc6e3f4ff52254310921b2e29ebb86f67beed8274310da7403ae570eb93f3df351c51e8f10de01df1ffef063e3a6f5797cc0bf11628d70fddcc34f3f15872647e720645e03cff0e269131f7ba2d3d3531092e7c3e7af4d1c377d1a52e085960f826bf3c4476717fbb67fbb1a213b3c3f77e5a409e38a92470d82f6703bf8bcf324b861d9ac3e0ad745709d30e9b1a766392e947d047d814bdaf8e8d487c78d9fbdd0017d5f23ee3d366ed634f6a8fc043cbf181e887b7cdc6313900c67687902bcc9d3a64e7faaf9021a0dd7a2feb8694f4e98d65df9279c2a70cd2621412b32b66643dee61d0fd9727f45b1aaf832faaae1939c96e36f9f360eb28ed22ec2a56a7443fcc1f794c77834f483fff669c3bdd651464db7ff351b779ae95094862621337cd38ed6430d48f29010384a084b56bc1231e847165b0f55c6048ef433544c9cd02d934ca92a1122cd47841aad07ff0a8afb14211f8a8b0f91dddc8d37288fe14b48f0dbf8934ec3f797423dd9389bee4647e57d68130b4555ca06f484dc0395902c7494c6a26a285be12b3de0f3f3f0fc26720915c1f102d90b3d0a456550be86b2164a05942228a29e72283ba02c855202cf5e83b249d4d152a43cb41aba5ac666233b7b169d606bd17439158e567442da804ec859702da113e441519ad7b23cb83f03ee7f0fcf34c271109a2e9d091c5939dc73a332e9527303bb80f68a3a951f506f3607f5807b8d707c508c45f4198ec78df651733d8cab4afa1ecd81ef1e948ad113707c42aa474f904f50ba38674e7490e4a0f7494ef305694be05ca94307c57de95be3f983e2393a00aed3d054ea455de0b3ddd221a0d752341c8eddc5b9948546b2508cc85e2c8963a07df42094cfa09e4dc0e4e982a670fe3e8c5796f7e17068f3ba68cfe81342c7055d4491073437485f07e825c61ca00f92058dd4c368a8fa60e019b63b4027e92be415746ca53314f17dd9872688fad44d2885c5031f1a03cf8befc1f343059dc5f7047dc551d05ab429686cd47909cd16f4953bc3fdb9e80d7505d475189edf8972155ba01d787eaafa0a3a03fc592ce82cfd8ca6496f01ad3a01dd16a34704ad956cd457ba0b2d6259700f8a740e8ed16890acc1b17b90cedd0d3a1b3c92a07e83be9f415d405ff624dc3f88d62af7a183ca1278ee55d453be17ee89768a40960fa1f7a58fd153a22d514091d245fbe233c1b3207faf0b1e2b5dd1202503eae802cf9c0bf607da32fa815011c86b919408fc8502e7f5f41bb45a294403d8e768b528ea3aa04112ea0525575d02e53ed4594dc1547db1b9515b8ed6411dd57716b2fc3fefddba2f23f20a98a91d81e3ede7688741978520a77aa028870205f83215a1c6cf106a9a0ec50ce7c7a530b013304eba0cad13f2898286128a1bdeb17194d034388681fda16043fe845e45afa1b7d0db20a10fc5b9e3a2e392e2439a9b8575bced1314e78a8b0a7cd2fc75f381e6b79a5f6fae6a5ed9f8e85707bedafb55d59747fec3deb5febda5c84ca204a37671f66a92d8bfa8da77efc8b80f47c5b76ff787cb38bb12578d0aaa2db3e36a9a9b0b464a916c54358baaa6896ab594e8fdfa7ffaf0ebf6ed06168c8cab6eead33b586b9fc2de70effe91702aaee036dcefd3dbf84c345acd12e1bf7f6175dcc393e29eb73fefedf6bc7d42b7f6a886ccf735dfe4b4c14d7f4fa43732e96f6be9bfadf4574eaf73faaf44fa8b95fe732dbd96487f7efe2ef633a757d7d29fd6d2fa06fa6303fd07a73f74a357f2e9f79c7e9749bfbd7c3ffb762dbd0c0f5ebe9f5efa269d5d6aa0dfa4d3af39fd8ad32f33e9176efaf95a7a91d30b4efaf767e9f9b7e9df38fd141efff4597aeeecddecdcb3f4ecddf4cc5f23d9194eff1a493fe1f4634effc2e9479c9e5e4b4fd5c5b0539cd6c5d09399f404a7c71639d8b1287a3484d6727a84d30f387d9fd3c39cbec7e9bb9cbec3e9214edfe6f4a0831e284d640738ad79eb6d56c3e95bfbc7b0b7dea66fcd97f6ff3991ed1fe36ba6fb7dd29f13e93e4edf5c4bf772ba87d36a4edfe07477117ddd4a77bd96c87615d1d7aa9cecb5445ae5a43ba1d33b1be80e4e5fe5743ba7db9c742ba7af6cb1b25732e9162b7db98856c223956be9664e376d34b34d9c6e34d38a97c25945117d69839dbd144e37d8e97a9dbec8e9bab516b68ed3b516ea872ff9d7d235abad6c4d0a5d6da52f34d0552bdf66ab385d593e86ad7c9bae9c2f95af4864e56368b94f5a91489773ba6c6907b68cd3a51de8f330cce7efa24b169bd812375d6ca26570a3ac889602a54a13e922077d8ed3850b1c6c21a70b1cb484d3f99ccee3d4d7fca7679f657fe2f4d967e9dc223a67a887cd49a4cf703a9bd359563ad34c9fd6e90c4e9f6aa0d31be8930df489063a8dd3a99c3ecee9a3f1f4114ea738f2d994fbe9644e273d4b27c24531a713382de2f4614ec7733aae1b2d6ca063cd740ca70f703a9ad351237536aa818ed4e98890703622930ee77418b43c2c9f0ef5d0fbb19ddd1f46ef73d37b07b8d8bd9c1698e8104e07df63678339bdc74e07713a103e19c8e980fe7636c045fb475b587f3bed67a17773da772dedb396f6e6b41769cf7a35d0fcb7e95d03a98fd33c4e7bf670b29e6eda23d7c67a38696e770bcbf535db68770bedc6690ea75dbbb859d706daa5b39d7571d3ced926d6d94eb34db4530ccdb2d0cc8e2696c9694713cd4837b10c0b4d37d10eed35d6c14edb6bb45d264d6b9bc8d28a68db54276b9b48539d34253991a5dc4593136952a28925d968a2892670eae5b48d8dc6c338e39d34ae88c636d01818424c118db6d028a06014a7910d34229f86c34538a7614534142815ca69087c29249c7a387573eae2d4090f383975c0581df9d4fe2cb515512ba7167308b3706a86a7cd21d4c4a96ea71aa72a3ca672aab8a95c4425f8500209f050b84b39582d3b23ed29b653c429aec1458b96e3b4ff3ffca1ff4ff72e1a67a31a5407aff75115aac0dbe1aa185cc51370a712b0db223403ee1cc1757809690ff7b6a36be80c3c5986ea681560a801280bee22749e11741d0f45fba08e1cecc6390a001869b0b44fba4faa91be07e4db459a2e9d960aa5e9388b6e61c3d9762839f428e0e9132816d5e02fd1747490fe40b3e821a9b764455fd2d3b40a7d0bad08f45c87cad1563407fae2c653d13c3287dc07778eb3d36803bca6c2e7a7f1267c067a77102f44e7d08b5422fdd0267c0ec65587fe8d16d2a1641eb8df2c520cfd3f0e759d86ef6f006c85d839ac234ed2e01ef41eda1a6fbc47d3f6ec9cf1ba86e641cb43d156b946762b5e6845506c3b3e82ebe5d5a8129da10fd227e805bc48f24a3ba47ea83c40015a0888fc1cde20be2317e3d93076f19a236a2733a5425c857e900a95f150f751312268731fb90f46548c0e419929db614cddf122ba047a2a3e8d46a79501523a7c1f6a509e159803f06f369a0267730061ec45ede95a540e3519e395bbb07fc3372ba4af61cce57839f9373a4d7ba354542c5d055a03fc406b0d58d0065ef7a3c5c0bfcd249316d3727a9cfe22e54993a545d24bd21bd25916c2ee61a7649fbc516e54262abb548f3a4fdda41ed388e6d5c66a27f42526d934d6b4d374c51c6abecbbcc6fc81f93b4bb4a5daf257eb10eb2bd62bb614db0a7b987d8dfd94c3eaf893f301e7eb2eabeb315785eb0357bddbeaf6ba07babff6b4f7ccf2d48674087926e48bd088d0fcd079a1bf8579c29e0edb1b4ec3ef0b7f39fc6f116511b59172e4baa89dd18fc414c4ec8f4d88ed1ebb27f65f71ebe2fe153f327e5efc9af89b6dcc6da6b52969f36a9b7f79bb7a7b7bd778cf7bbf4de89ed02b6160c2fd090f24bc9af07362726256625ee2c0c49989f312df4d3c96f84d524a5246d2ce64963c3a7976f291e47f25df4ca129a6940e299d537aa6f44d294bf93ae587544f6aafd469a9db53bf4dfd67dbb4b6256dbf4a6b9f969db63eedbb76a45d9f76f7b4ab6d9fd47e4cfbb9ed6bdbffab43970ee33b4ce9b0bc83bfc3c60eef763896de2d3d3ffdb1f4aaf4cf322c19033286672ccff8a26346c7591d17763c9399909991b920f3f9cc173237646ec9fc392b27ab246b59d6baac2d591f655dcabad129a9d3d04e7feab4b4d3ba4eaf74aace0ecd9e997db4b3bd4b519737bb7cd335a1abafeb3d5d27775dd47575d737babed7f554d7cfbb5eed7a33c7949398736fcea339b373d6e41ccef97b3757b747babdd3adb1fb23dd4fe6f6cd7d2df7468f813d36f4f8738fef7bba7af603545accd74ac56c2b60500545f8ccd24d24dfc42a9b4724945e7bb6be23b29fad3f5b9fe172c43b12e31df1c5126a9c4e231bbfe56b15eb8d5f9e8408928015818ad839a84343d93e9b82164a25445518a6a0bdbabd7160b569e8c80310751fee3a2ab73e3327a7234abfdc782a03ef47a63813f8d03189591eaf23cb41bd1467d7d5d5b9b7783867e79a9ee02fe109a2f2a3b48afc60b4a0a07c9f8de1e72454a24a4c468c48aa68c1397460b56be803d00c11cd345e145dbf0ead65609f2d43f369055aa1364dabd4ded39431d8e185f1781d786a1549a88286ce913451a0a54d08c9a1ec5d68291615fa3a469a509922456b2cdc42ca425d368f2336262a322234c4e376391d76abc5aca92dc03a420f93e3ec8da742c5f872cfe6e636e68af7daccfacccc0c9fc3844dc4643659dc528423c2e98e55f1181c4fe34d38de9545e33df146f1ba8c921d6f1429947f3e1427f69e841326574ec45df9cbf7e19efca5499513f985892f4fe24771e150fe2e9e5c4c17f1bdb48c8fc39bf9b80d7cef7a3e1e6f12653d1ebc016f169147153f233d26bb513c4a41e9e81ddfb0364437e9c9382985984c7a348e8922e9a9e9912435353ddfe5b0b7d12353a550596b1bcf486869885cca1cde88e74396d851dbe719780335448f5152239cc0f236768d622549b5303943704213bc66820903abcdc015fbd0070656db0cd630e41312703d34b73134f7fae57a2107f5b5672fd767d6daafdaaf3a9c398e1c8733144a4e06840d8a5dfa49b15b7f7284e6b41ea49f46b5c15eda012767c7e05047079cdda97397ec2c0f5c78e0a623067bdcb2421d563886843a7ac2e749645f119efcd729c59f4cfdfcc4df4f158dd97dfffd6f3c78e9d34b9f163df5cc135fcf2b99c3cfe0f6a47dfb7dbebb30fe3061d7da570e597fbc22c546bed1b683c48779f755ec3c6283b06d8365cac8e185e7f810c7e3a3474e42309c279a2f29a9e0234c2814795132f8c325bece09b6c4a4c4245b7242723e7ac11cf34287e5612f24c82f9897273997a524acea941c1f99a8518bc7aa596cf196346ba4c5d6d1d429403aa12a0f08bac19b5bbc59c59bc5a05e4741d3dafaebf5f6abffbe2a08057266bf9c793df7b271c77e354033f6932840a5363290202bb333502039130456f6b649026add7e3f310b7b5db77dc63e19f1f0c323863dfcf0b04d07dfde5879f0edc675c31f1e3f62c4c345b46365e3e8cad84d87dedebcf9c041b26acd730bfcfe050bfdf32ebefdf6850b6f1fba40c6f9173cb766cd73256be7fdfe2fd972e1ed77fe7ee1d0c18b427b4b9a2f310e54d250063eed5b6bc15673a9c3e93095ea26a7d3a19522cd13e251b0ac9686847808a6b8343a261a956a2826263a2e96c4c73874970e2a47c3dc0e97aea844d61c2e974e30a128f01109f3c0276e7137df69d2a88cf4189ae2b1ca29c9b23f2ccd9fbc266155d832ab4bef60b26aa883d3936c8da11d9cc9f156870d34ce1969ef686f04493c5b6f3f16202d48a21046a1cac72efffb3ba0aefd9890cf50f1df4a681610ca3b0e77de53ff4382c59dd6bba3daecb565623cc6b75731b1365a6a148ac2b124d4d416b5c549ce6ea893b3b7692c1a8547ebc39ca32346c78eca98183307bd8436e0f5649dea37adf6f843fc6dd6b78fd54c9a59759893cd296124520b37859bc31d51ee284f48746c66324ac6a99ad7d9d6d5d69de249cfecae7572e6b8f232076883dc033d7dc387640ec7a3b551e661ce51ae07631fca9c629eec28cc9c81679b9f71ac46abf13ae267154a85ba59dda0bd64da605e995999599d9933068dc1869a812c75d1704fdc254b260af6265bb1b70d127a696867566688504daf2176f89707869dad7c687b7f3e073776cf970f9a278dc1a18de5932e2ffc27ffa8b43423f38b9afbb70d1bb1a9f7e485dda9f7de9747bef0419e8f9437dd1855f7e4739cff895f5a3d6a04767d36ffeb87f39ecddd723421617f7ac7a923b326222cbc049e6a78892e3e1d3f874a24e11ea4ffe21e0ce7500faec1e26305ac904d632b5925930dc7004e21e011a0c66afe0b99233b91056ab4c92fa275568b82a853462edd6abf28aa841af580adb319e7c2c25dceac7708270722958165e2713b43bd4924bb93b30b9953ba60e1a2cab5fe35eb64e777bce7f7dff3eedffe888f7df525aead87f6b6427b538df662c18f8af6148c4c4ec9a522682ff7faad7a5d59214e8f9b28dececeec4e642b54e95f5bb968e142d959cf73bffc8a77fbf15b7cf4fbeff107506b0f32801e01fd73a0c1be76768b0949664d91c071d2f5cc615eaf63eb2aa76ad6a9263b28a604b96d9249735b64a7fd6ceee5cc8b50420db32c8876165c6a6d3ddc80eb0c6cc14a22908c25b7c75d1838f0447a84afc713bbf1ea277975373c91afef860b9ec405d2971f1c195fc7cbf0ecbaf1473e78b80ecfe66575d0b3f360442f3009eca7d7e7401aae5028231e0985eab24735db2f36820f155ee22c1c6b33b0035ca470ddd9f10eba9bb46f3ab3a3e90c448852d3992a715205510a469b9a9df808e2609dc37d66ba092d94219e0c47613290edeca900f5ba6479c0cd5e3bb3b5e43ebe8b1fc63ef85e11fe92cc230b417a1cfb5105913092ec174f190028c3050d1791c8a66fc9c2ad6296e102bced8636e0d9b7d04222aa0731133d35eaf65e38738673918b6bce277b0d896cef73a3080c262b82229a4f3683701284697aadc15090c53b6d37d865a25635dd0051fcfd316143cb9a2f49e52d9ec6e7922b9da8d2bccab92c4c8bb2c5d0284f6418b47f5dc8f565e12032701be2b03bb33201a490e44ce4b023d04978274b2b366e84ff8d1b6f628dff76f326ff0d6bac809fe6a7a09c8686b370279c55c9a7f3525ec6a7e3e578367e062f17a3fe1a2169348c0684dce7c9a79512a964250aaad4d458390a001336d9cf06f5000b3da8af0d9024f3ba8090304018d83e1bb549644c977807cb4ecc120ce57800c8cc84937840e3d62a697abf9a7e0de7aaa002884fa40130e228b4c9971c1e1149c3a21c202a0ec6a47cfbcb8e35964af72a09e25464074fa04785daa91c2d54dd03aa1e12f49fd0136a78cdb3f5870f1b0ed3e8cd6de4663fe1ea28bb6189b12f7398349c0d579e919e614f4796852b10c5864b1152248b7a0a3d2dcf88981ef954d402541abe206241e482a81d6847a4038c60220c22bb33ea62600d30734a764f9c9529091c2223089ddf6f1c0464cc1a77cfaba50f9d99f5ccd99157b0bbcf03e1fc7a5555d54cbcaadb63ebfacf5c9bdfeb54c7cc2b1f3cb86d5a34ff11465f01fc9e0ea34f41d37c1d90c7a5976ab1a571ae4a8fa5525b2d4755c6adf6ae9297795e490d897221ea0e8f4a8ab3475177ac26a70a22840c6d19bf668c1f0800c623d410b6facb00bdec864b0b802eb0835a51ccb8d8717145f112187581a1a4f8364902620570421ace0e9cdc313c9ab7ea15fe31bf32f6f894a11f3ef6eef103db76eff76f7ae5c5fbdf7d72fa8951df61f30a9a185bbbf2f35f12138f74cc5c5bfe9c7ffbcc69d3e72424ed8b8bfb64efdcd7845c170197b7824c11b07925be686ca11644a9251f5193520911448986cd3a8a9255c96c585cd3d016386416033b9b0bc6c8f0d29785656ac58d2780b927044bdb9a505bd40f8d4293d14cf43c5242701a4ac269b4331e8c8798875886e3623c033f4317610bb05203449ee510c188b03254e604f36c7eeedc89a6b12cb1f1123ddd98b58357e2c223869db9241541cfa3d1589f578a501ca5f6e8884ac55d695f622195a8c4b24cd91a131a85751a0541901c636fc4b7f3c57e9bd7b00b6d0116d96baf0a05161a0cece1b501ee08e3e31034471ec0efb7b34570e3731ade54d96e64bb069cc0cff29fc71e9934faf023af9f3cf9fabd2f0f65e7aaf80b361bbffa8f7ff25fe3e2ea3a66ecafa8d89f9004d42e87deaf35ec49021ae94b70c9c8526a469521726554c8367ba579499b5551cb12cd6db4a8f01857148d8f8d4c0403034274d93031971b2fdf121f9fbb0ed5e1d3e4343d2dd5b13a19c6bd37868c81f8e636a8890d0c4068cb40bc71c21cc5678690ad8b376f5e0c056b835e1af4e1195bf7bd8f7c8d19bff60d6fe25771018e1cf412ed7e70cbcb6fbffdf2968364764d4212ff85ff3c620cfff9c7eff83f0c03351e6f8b11166a0748d324e0898c1ef6853107a1843a24b0170cf84119c560d4650542b45ac38fa6ff87d9150c1af90e0499c2212848011e39ba741de5738e2458a6112c87f563136935aa96159016600cf6e2f81df470d33767306fca62e7863794b034116f2d05fa2e35e8eb8578ab972f310ca89b2c57c6b4af74ae8a5996fc4a469839a16d942721caa681f506136e8b8f84f809f07d6dbd41d8165d35ae7240496fc7ed0259256419c85d31d4d5db2601b096abe501900cb274e5b66d2b576edfc6b72d58859abff892af2a79e115fedb6fbff1dfb6f65bb570c1ead50b16ae22473794956d78a9b46cc3f0b8bdf3dffcf8e337e7ef8d6b73acfcfc952be7cb8fe1714f2d58f01494008a97ca60446186c47895d8705c8ac22bf56d52255a12125b695f15b22c51898a8a77c5a0366da22c86c040f75b7cd277fcd7167909a90dff20e270e4e1a8c3d11fc4d4c62a55ce43ce1f9c1424a68b21db4e571042a2ac8094b449c22dc3021a7c3da86220c849b7bd8f7ec56f62fb37103138f81efeeda00adc33284bb12025804e9cc31fc4b61fbfc321863bdbcc1f8821eb5a2449589f6b20344724af915788f259e585d27670e746e2224cb503f6c8141ee37ac0a90bbb70edcc19e1da252f17b90281348c6f6b28d1e702eca06c9216a2ed10a2301c0e55e8461506e8b8dc28bcb22b508d813dce08f40115359d6f4120e7d15876017a20a37b7c6d49059528ae405812078299cc5085ccf2994430627487fcaa82094a90bc20cff5990110118c4ca49f6e4519225ed68807676376e1e60d496de08cd06b7c155fbd1f7fb21d7f22a8701e17b20b744b900a16003f7285044390905710a136b3350b049648bcce3322ea69e074cb8e6b5577f47c882f4dae4000b928ab809ea30ac03c72059309c1f9320370c9a41df85545260950bb22e87347d7837d0e1415faeecac6a2f3468b924cafede7e9db79fa7efc18f47b35285a35482405899ce04b4b88d164498f7649c85dea5a6cf787ae025e4647583426e931d81215214501675152842b517812b3b0bc2ec33b0230ac37344e4478064ab8fa6f7efdaafd34dc123077ff6ced19fd99b8409ecae50545cbc3777a7ba18836888614088870595dddd1f7ba8e1e9d93b5f0d1216f8e1bfbfec49a2ffb8d1e999eacca32e778d586090b868fca1edb71d4e37d7b1dcae9fac1e6414b860f4fcf0ef7e47612488f57284fb02d60390621bf2f33cc4cb59de19e48ba7390ad53966d57c6ce2e9e5d093bbbf4ba27ab534c044a71ca61e69488b49894feceb4b629fddbf5b8c77eb11e840d8c67ee3143df0481cfd68a5b3f9d3d663f7a3513dc0c0c2c0305120e46aec148d2b85a50d33be89ee6c3c0d67be0e50b5840cd36387670fae0bcc11298f5dbac0c169a9a140cf3b2b3020997e4a404419940e8132289f8305416262a3910067506d3258582ddb24380d6b062ee9ce52b9f995d4ee2735f9ab8ebb3bfbd36b1a27bf90bdbf27c93f8b9ea39df146edc33fdb1c9d8bdb1e4f749a39fe5e75f3cc06be6cf2f5dfca7127cdf3b67f12373060ee11ff02b24bcfc95ad2b966ddbcafbddd3fff70f3f6c18386861535cc8977b1e3954b070e95dbe62fee7f737f37f4c99f4d8887ba78e9bb8f0d96771ff77f6e301cfce2bdb5d39febb39fc77feb18c8cf540884d3210898e3ef0dd851c100880d209dc891d3ad591830042d11500a3b2b8a939a8ae8a0f00b3287e815898c8091a29418de980896b0319c1cb67eb9db7a70e5a0fea4f2d2e2820f37be3cc2225906fc33662536caa0d8d444fa3696819d214ac12996a52080e27c3f14852609e88279159f86932973e29cd5466a9657831996f7e91aca76ba5d000a411d1048da75e72885f25897cceb724e7af8b9b1e5a7c8e599bc2e9ee86343c8f9780169d00ef590f235721528c039fe50d477e5df33b4bb05f7f3dd66152892b3c96216b54080b8feaa0a128a7142f8c8f501f812d0d786de4a77232f6dadac01820620b084aeb4962fced4e2b1eafc6bd5fd9b8f1157e08a7ad59b56a0d3711e9fb86f973fddbf8b59b4d57c889a6cfcb962e5b448a79cfa94f3e316dfbe13d4bb6b8e3ea5efcf0ef209ed39b2fb164d0ff70d4d9176179d9ba5bf73bf0cb68b704aaef5816a1845b5086db1e21ba18744281dc59c63e5b646c2481ee094c12c4219dbb78acad17212cb9f8fb05cd885fc3768c167c5f3ce5a7e7f8ebfc195c8aef2ffd898d3ff7d0587e9cff8d9fe7c7c73e74a65f3fbc19031ff0e6bb416a808aac3a48c50e3e0ff26b403fbb4aec3a62e1964c14a5494e2356031d0c900cfccbde429741aea0bf4b8c378ea918afbe0ed62f967fcdeb783eb4b217afe59378011fc7d26fcec461b8036e8743b7f3757c3eff135f0b34113c5c0aad9b44dbb25f227e54a2faa5d77586350590a86416e4385b5bdbcaab8cbdb11668db4099c1728256374590e34d39e446634f0122fb56355daa0ad6ee85da3594ea73066b975e07576154ad07aa0e0c49546c33dd5eb1f7041ddd348d1434559f1475f6ab6aea82825c1448291ae5f8e2108bc47e1ae9579d2f3b767bfcd655eab21882a21c9da4acb070931d40747de3e5c6da566ef2b386294b347202606282fc93426fe7ac7484ef27ce19fcbb4abe85cfc04bf1d817b032755ae3527e95ff845dd8f9c88e7378d5f6a679f70fc3ebf163f871bcbe5fdfcf1e2ae41ff14ff85ff947898191b3ee065ddbf9dcaa9fbc2ea1125d8661b3ae1a6e216ba38117722fc349c6de0283aa10e23ab202d30d274e922f4e9e6c6a03a36faa20450d6982c22850375e6d64093abc85de20a23a23696537664d8c48dac82c609f2583051256e56c339345ed502bd4d700981337afe5c5463d2694ef73990852fcac1a9598992ae704bb78479d970dcf00c0445050d46df1590a2c859672cb668b51b75d0ec67d274e9ebe744f5ee9e3d0d06afecbf5aab51f042932c5c806fcec4b511d804f14870c2eded1622df355801a14bda1c90025645574c11490102360cb1559a45b69fe16032800cb5e950a03f8829b6089686a084961296a17d2997552ef267d592f751899489e2633d942b29895ab6bc84beaf7c40376916972240d57185863258ca6b034b9add259eacc3acbd94a86f92eea93fa309fec537ce6f1b410228589ca4c36cdbc942e652be472a5dcbc816e94372afbe99f95a3f4a8f219fd54b9427f90aeb07fc8bfd11bec77b9dd9827d098278034385ed85583a79bb0d4144923f8bf9bb204679790994dfd1a2f91bf34750cf2561254628010cd86bae028da0d49221b1598ffc8f069194a81329fce97a480c080029e249f353e04e43e17d43a3916ea30a3f77c9da8435115e2c04415074a345d03b7a46bf9ba42a80ae4564de07fc0f9305d8e927aea40758bd01a61a105d545bc7c5b06bb15288af867ef34aba0fb702a9c8e46740f712b2e3d892429714a921ea77752b2f5c9642e99a3ccd6e79305ca027d250991b089ba7024f5e27634594dd13ae15c3a5c1da54d50a7684fabb3c1fa2da77efc12751b1113904de458bd8276b83d7e16cfc3ed8ff279757c5e2d3bd7a8d21b0d692cb61149a8e1eba08c6519f666b62f467188fc990370453e0c1506ca64ac9028a9b312b43d8d81f468ba31c7784bb20c898a15a6c897d1997455fa91bb95c9a458994f14196bb20747c87d717f79041e294fc093e5d9f222fcbcecc71be4cd26bbd16730cb0e83d9d84ed6d6f26b4d53a0af3763a5af1bd2a4af6fc682cd1736ecfc6dd939bf13f903d9b9705b160df7d8c38ceedd969d13a629cbc8cb2507cc94f14e932ff2264c2f5ec498375fc4ddf02cbe981fe34745e6940de235fc5bfe1dafc1fd70048ec4fdb6f207f82611d5e0ad1001430c1cf03ed272c3fbb850375f18781ee1809c765d2592f03f790ee180dc016b151009233be733d93cb19e3ccf439e373cccf044adfe5a024f9d06c3c7abf9f20d1b96f3aef8c39ba27f37f94996def49717ca4a5fd87ee9c2e7df34ed1094e03782948846f7f9da3aecc486cd16b3155b2ce67c5b8cd9204d1890c6126389b401b60d8f340814d3c23f611becb50699726e834b508c1cdd6d847305a61a6e918fdc41be3cac5fff3cde6b0f500f7717d4fce43f89d8f017fef9cf109d6cc3e304090d9236f21528e8c987022d5d280aedf16503aaa3baec10a18d03429b7c59421e2a79fc9adb6f2931494ca60ec0442156a687874b8e3cb71e6596a20d42d70a4a3b02de3e5790db99e3fcc3e0027341be1803f83de3c20c31cc00ea29920779b09b84d050291125e244924493e52425494dd2e2623ae3cea42fee4b26b119d20c36d3b5585eacbc28bfa8c48e31d278a12e31539a664c77c709d8d5ca56bafcae393d4f9f7f6fc0d259174fe20f316a5cd8b484bfe0f7bf400e85acfc139f84e7ad1ddfb4849dfbf46fcb0f92214d57cb162e5c24ec99c8436f01fe26a33ff9722d6662359198d81855238a4e626363f275534cace4c1c8f3b27b4d98df21f9d19a4400632931ba293652416d22c3aded9570779b14fbc55a60f865119f04fcd0f5e034e6b156f374fbbc999828033834667f6c6a7aea90541ac06e463a20f6bf242cd3714b8644ea37fdd443dbde9cb9fd996f3ee39ff3efa7fc3c7f4efd93af1f2adb30e79b9338f4d7c97f675b8f76e93cffe98727c486a79ddf7ffeab8cf48ffbf45dfca7c7e7c686b53ffcdab1cb49c2b736805e8915080a1ae0b3ca0143ee03d0e363aafdece5c6cb861e6566e081d5bac820a9460649456a4b06c985b45864070312abd8359f364ddbac696368703e43967e6eba5ad774156051c339913fc2682f58945468cf817cbe1095384c88f9adcb3454e254a3f4aee04bef72de72e7c69456c0bc6406712504adb1ae72d76617152e2510b081190b68cadebadd473ed85dc7bf0445f8967f098677c6b53367aed1a58d0ff28bfc53dc1627883eb44442327acb972c090f4f1d84067cbc58c50c5e08a37c2ae13790087710031cd812ed8009fe1f7c4c812a647c3ca26de9ddd2dd6c347d962ea48a8c14a24ac21abb498414c1daa2249c4452a5549628c7a95d5116ce22b9522eeb22f7437d701fd25feacfee9647a1e17231992c4d66cfa0a721089a2dcd6633e4f9ea8b689d9c0a3a00a18f06d10f19d074ec0c3e8ffffed7a6e360b943a51f1ac4ec5e6f8494edc2afe239befe2c4266e04ba5085da311ba49271158ac8c9085bb057d6741776b86a71d0899f3750037327821936a36e99a1a5803625290c57e36b802a43e33f3bf3bdad6636bc0870cbffb8b4c6446744054ba534f6109e0717b929eac939ea10f22f7b07cdda78f2253c8236ca25ea8cf21f3c85c368fcdd7d7123f8b569046c0fb4b32180e047e5102d95334a449ba6e46d608ea913c6ab8d96e8d93e2599c1ca7c4a95e2d414f34c559e3acb9a41bcd96b25886da59cb31e59933ac7d515f3c80186889e583bbcd577daa4febaddf63f6597dd69104fcbbb9c05a4c26d271d2785628172a856a9156a4179966021fe6905974a6f4149b2dcf5666aad3d459e679e679d6525246174b4bd822ed7953b9759db4d9fa86f501e15f058b0497bc1af6f63e05663ae792783bcd9770b0dd1f70e09853ba2a0a60037bc33531a3d98ac68b7db24592916e06c1bb0851cdbef9689e4ec6805e1ac85370216360757ec1489fdb80a79a03786b60546023289562af6ffdf7b9e12305a99aa420a64932263a95b10dfe46053b29ba884bcee3e978c6791e47d079fe201ff577e2092e21ca6abc41e6342da2d1c2623482c5f8def0c46b7c2941548c0913074a803b428cd47c016464a2483e06b644d10c5be2fcbf5720a40b61c965c44db24906c900bef5253ee2633ef55e722fbb579d409e23ab893d0447d0583d09a7d22eb82bf5e910a1d259749abe5917531dd4a039581fe93cde845f3adf74ad0e46b1811437fe0271df71a1ff0f0295630df4b5d21769e04e55a4d4f355b07ed4cf40dc70be84645d64d3442649372636e4c084db65476b707b678edde7031957c2945480950130d64fd51835a9c814422354bb29dd944d73d43cd3dd74803ac4348c8e528be96475aa69269da5ce336d36850453ef62da0dc74f97fc8d05f4f8cd1eb4ba71223bb7e1e6d4aa0dd2aae0dcfd48d90d16bbbbcf26ed94f7929d680f84aab417525bf37f462474fbf200c396369eca34e689af1b294f91b18dafc63bae5de3505ff9ef8de57f9cd9055b01772228d006ff1f667601b4e02a636a57cceccaab059d8f1bb3fea2a7193e3bdd89f732d153d44b92838bdb6c81655462f582b182ca58dc66740f43e00b41603699ca47fefcb3ecbef145b92c89fe9da73bd805c37687f97430d1a844a118a4fde229a357a740ba82e24c0f91d813bc1fef778200b39bcee0a57c06692f24b89e474b6ebe0bc668fb33da09f65eb28bbc01a0450ca497dc37ffc67795978b115449d7c812b9189eece8d3f03ef4a6447b63c97e31b8ce229869b41aa945c9482d4af00aa416451ff0541cb19e1f948bf9f3f86918e41c4019eda539600913d1215f7278ac2954b3a29da1f201ab23ae34f660d4016f8d6359a81985d2308ba69a62a9eaee930424397516ac6e40f20043365e17eb794466d721e096eff18ce88c988cd88cb88cf88c3679c9be685f8c2fd617e78bf7b529882e8829882d882b882f6853903c2d795174594c596c595c59fca2362b932b93af25c7b47cb5e54b2d5f288c298c2d8c2b8c9f16332d765adcb4f8f931f363e7c7cd8f0fbb7d06ac07ee026c6a4d96c6df913c26ef7eb9ab64eafa033535798716efaa6bba89c9abeb0af70f9df0eee87f5d2359c573c64f3fbf2f7550534955f1b8f7b7bc73d8396f69870e55c9c98d02a51e045a6d05e931014aedea0ba707cc36ed40986799ad26725d38723aef0e33cb6a445f0389665e37320997c51cd3b1ab19fb0b63e6c754c650e867cbdc0a74151b537400a7a1afc942fae9b7afbef0c2aba234ade8b667ce29d4dc7c6ace9e6e070e90f4baefbfaf8342ee2b1ac70ff11bf03a34ae6807f4068bb571f47be06138caf345a252bc58b2965a16eb071cd281d01a919e735a503f779f087be3e596f49c5d24dd7fbd2a8291487be4fcc8959195910cdf06f5b28269ba36c1341dfd7ef0c682378f1d7bb360e3e07bb68d6902ecd21ecbc3b648d9bbd2d22e9d3e7d292dad2a21010664c54edccd0bd4825e49a3a17ff600b5220e20abfb005397596bf03a80d84825773b9ca63ed1867a6566b652abf60e6a89948ec14c62442321b767c4e9969a9a6e7be6d635a3e6bab97b9a8e03dd76ec00dad1fd64eceff53b8ac6e1de588557ef71dc13245fb05ff3805a6e1489a6f91200f36ba5ea62e6d989d901337e3bec80b3c6bc2c2ad243548f8a0612a7ad4f94d1c5dae032c0ebf58109d9eb8119b6d4bce869d195d11f475f8b6679280fe7913c4f5e246ba7a4abe95a3b7d2a9a8aa792a99ea991da98270481e30de07c2b050a02a0184457a4798d7bcda7df9a727cfcc31f3fc2aff3e338b5f11bacd4906d8b371cb092b1a3df3ddea9d3eeb6ed7057ac6317eec53faf5db76ff7266115d2413c6f00ad5d68942f8ad9b159dd29e332b4ce2a1fd2894b418ac6548bcd34c82d6c9c2eccb129608eadc6b9b15cb8b631b7b6d61958329c29e6d0329d06b8f5790a3c951e11064027a37100487bb3b38472911bd50fdf83d3f92707aaab77bf23bbd7174c7ab8bc319d7e523ef8edd704adf9706934d0da845200cd7bc3cdd19ab3d41572c0460f24796b920f69076cef4444278523d57cb7ec74c6f54935e66503e2507b392010fc9c31b70252d1767edbcab67fd0a1503bb9158ff4c0415171062649e8966dfe35dbb6adf16fabe1bc61dcae7befdd74df9ff7e5ec9dfb5163e34773f7e6d4901e1f5ebcf8e1f18b177fe4dff01fa263de6cd7f69df71e78783cc0223187dd6dfcc35582be0701611419f4ed047aaf216ac57299d551635ea7634018838565ec6b84fa86dae78aa965b18e2b636fa1c7c8367b1d812e3bc4e26bc31249453573e7fa771d3890ffe68cf78f91ad4d0f924d9b37bdbbb5a94c76376d9a50f4b3b038ef43e3b365b7315f9806d1d0bbd21e748830ac4aa86febace9e5469154b0b7aebc66466ecb98447dbf06fea4c29b95b2fb07a8aff9021f6ed4674236d4db1765220ab2be6b56cad83be890798f5db533798805ab66d4d76ed47e39c7796b6edc600234e4f0390a1c858e698e4043ee96dc65a0c157fedcb7e3e44146abcb3e3d5c316ebd9cf243908215d0b20e5e26f57fce611e42eb5a92982aea7b6712f3f2ff98c4b41bb3380f494457434832496569ea700298599d4e66b20564095ba1ae266bd93af515e214994b62a2ba9242932591b74c537ce649b4d0bc842e02ccbc5c2e5736d0754a157d95ed578e2a9f2abfd16bf437e99a14213292222129d02970f4e00192f863d36ef2c8b5a6e3076477e3647ca9e97ad32ee26dfa1cc67b8b736dde42eb88184debba359fc5ce5a56435e6372805dc02ad9fd7b7d50da9468d09a3668b42f49766a613624472b1e7359741cad893c146e5790c3a6aa728143b515448581cbf11ac98fc6c6fac09c6a6eeee5eb46fa5188a0cf95915090302d61654225bcde4bf832a1394103990c4ca6de2e99b744d41310d1d43e8717bcf1ee812767946f3ff0e4cce5db0f1cc8ab9efdcc6b74c9dca77ffd4608eccb154260c9a62d2fbdf74a539954b87be2f8b9adfa022370a1ce77eacba1ffae2f975bf4655fa1e72f1ef2478df1fc1f34061a160a13b0ed330c7b130af6c6251f70a203e61a911d74daeea54e4f9f3facddf379f3c2e7a039f23c659e3a4f9ba7cf33cd31cfb3ccb3ceb3cdb3cf73cc7156865f0b77dcb9bae68e257ed3d7ec7acdbf7ad7aed5d7b0935fbdf64ffe3376d02fbf3f71e2fb2b1f1effa1827fc8ebf94f60c873c05ebb71578121c0226e851e0aafd8d317d9e2156baccbf03bf4503478c4bb0ddf781b8ab05fbedce2187d5ac0337e1523e13189ada40942883ba0c5f403076e2108d2b50557ec68da2deb55b76108fc638b6bbcc35e1bbd6b413835b66591ef841f8a36f0cddd80746ef3da2dbd3bf687defdc7d475d0818ba96b2f4e6ff1d564fa2d0fdeada6a615e734edbecd7d1755fdfeef8054d101d03b07a077b76c022d30d1326b8d7648d16508f3fa3a85f3302c2278ebb3a7847bde57e0daec12f214c035b78429940e88eddfaee255a0d2c145ae0e51749fd351f76ed35e10a5e2871983d6a602aa3a0ead25a3ef83f9b7fb83e9b7fb6fa5df006d2d91dca59e2561026d25d6dccabfdd17a95a15d5dda64f8ae8d5d93bf26fe0d37e15f0cb7967fead25fd869285397b2c4a8f3245993b008868676a67eeae75d7bb9bba9b4d71280e2790143dc5d4d695ee4ef7b40d498949894d8d4b8d4f482ed54b4da5e6528b53fc420721b22e9ba8995aa895daa89d86d3081a49a3a4682d393d352ff5a1d479a9f35357a656a65e4b0d8348ef893f26fac456853f26fac4ea03ba74f08ed14b968c5f9357bbedb7bf8d3ef268f1b1710b964d78cdf7da8b5f7d54bc4fcadb9d923274a8af7fbcb5edfa2515fbbdde77b3b347dd3bb020d196e05fb06997b17eac0b88db2f6c135808c08656a6dae84ee4c087d432dd0434060db03badc24218b0243318e006962082577d23e055051671877417c824295b6012079e89e7f04503a7bff3ceb92d65656c13ffa0bca972c9e00d9bff4a0acb714f21e3bbc1468c346c931be2d5a85bd669998e0fb96bcc609bdca6c160a5fa7a8490e70424ea7266ab899aea392c4c94cb715bb62f1870e0ddc244bd5e53d36bcf8cf73fc47fc107c9f6a6719b37bfbb95ccb959b9abf8e16b74070a645500831642cc78d397fcc78c858c6491b19045c6e23d910a24984948112b7ef5db2269f750b102b73592fe3f2403b16f453f3285885c5629994f5691ad44150d695433f2de1134424a422285912ac5a9d9281b77a3dda40c55e4a7fad3fe525fd64ff6a9c3d1703c8a8e920ad462548c27d3c9d24436492e5467a0a7f01c3a479ac19e9117a14578095d02beb4545e8bd6e27564037d517a91ad9377b057e56af5b0faa5daacf66cc947616f8f23782c1e7b843fd82015360ea5bb6e560285860301b2814266fca3af3f1b16c8180ed3353a4c640c87fdaf3286effd978ca1a0e1c06a87587fe36c5d89630a9051d01507b65259824b755aa8fbff38d1887dcd8c849010d646cfd6fb93feacafeed31f200fb0617a81fe38799c15ebb38117b3d93c5646d69317d91afd1039c43e22c7e95f5834231a952513d355930607b38784d310298245aa919adbe4318bf9092f49a6f152226b23b75112d5642d418f3779cd39b4b3d459cd119945d28ff6957c527e601e56edadf5d67b9b4456517071382990ee65f7c9f72905eafdda507d98e9615484279029748234854d91a7288f6be34c13cd53ad33d00c3c9b3c4b6749cf0277e7c9cf28f39459ea6c6d9e36477fdaf4acb94ccc0c5bd7a175780d594d2ba49798981759affad2d79a375bb7a3ed782bd94a5f935e633be59dca6bea56f31bd63f933df41de96d56a3bd67ad2547e829e9249b6d48442416ffd86bc2dee135df7d7bfebb6f6bf885f3fffce53cc8c65a3a45949b95746de3149091eea045b341464cb897af2f13d39592834a8a383009134c1d04d8ee80277587a6637130e920329a0304265f57242ca9a0612478060a616e11105beb522d4720d5d6a273b7d26eb58ed03f4caeff5124fe53075fd425498f903c7a92de43eaa80f93462823f562fd69fc8cf4b4f294be5c5aa0af97364beb9417f495fa76bc537a43daa6bca257ea513a9518e88029827a98478b30a5d22496a8b535c559bae11cda857552444639c3d29ff6657db401269f6594d055328a8e60c3e551ca7075b836ca5460996a9985e7595ec26b94d7f056a5daf217cb9796664bba58be44bc469e0a94522ae28fe0aaf3fc203f781ebfc99f3c8f5371aa54d8f465d3fbb886f7230348087f021bf9a81e80188425b3e1a5be5e8a4a3407b209322364b33a6cc86671982d481cac16505cb303d436df62d2ecc8c4cae83b56d321b1b353d7405b559b6433d95b18a01a6437dd4676536079bd41f5e0ec8be38ea9bd3f6823fb293453d0fc9a8c982a6bd412a2875aec16af25dbd25f1fa20fb68cd646eb53f432cb7ccb6a8b5347d009d03493d5640bc51e6297ec2c54779bdce6086b842d192580cf8d93e258aa9aa225ea09a60473b2a5adb5ad2dced1056c6536c990325857bdb3a9b3b9ab25c79a63cb70dc857cd8477cd427f9821a98aff5d1efb6f4b7f6b7f91c43d1bdf85e328c164805c09f61c09f11da08d0c261e651d651b60247312e2693f4c9d6c9b642c71c759675966d097a5e5b645a645e6259625d625baff94d7ef306eb06db56d356f36bd6d76cd58ebf38be74343b26002f99150782b23c6c64fcc9eac16be6ae7e74d0d0ac78de3d606e277df8cc867ea543a5c18d6ba8f8b9313412d0d505e0a48636fa22d4c08a6e50967c75273a447732956224e1400ada1458ccd8a20bc1dd59868ed466d6fe8fe9e87c611193c8dda4bfc24caacd144623d53435ced499e6a8192641ad3e06b57aa923e828f52153212e24c5b4502a64e3d579a6f9a6374c917724a49fa0539a06917d8dcf927d4d13a4c21d8d1756efa08930168cf85e2914a2af0434d3d729dce631c9895a84dd136d6271f11499766a68273eac7976baf6249a359d258484a3689db9881bc585f7d26d2c5188a191b60e6ca40d8290c0a2d59ce04acfc6fa5a1144002670e6b4ae68cdc9c07bc18d8e610293f4c02d1b3ae0ac73f76006c55893172df0b114daf3f79d8faee8d1a3fc919dbff7ecbd7cf8038f4f1d3d7cf9bb2bd77cfef3baa7caa7fbaf7dbeba7ce4f21b1b578447aea8b8217ec20e638947e3dd72344496ceb730da63ecbcb31bfbc7c5466fb1e46377951c7dc3f8b5b4db2951e6eb1c9b181962b6a991264fb84d62711485ef8c443bbd87236d3b1d7b12a3c2233c360cd02bc2e3754a2822d6d30bd4544a6c051e5280d946ce480ad02513081324c97fa54c607f67803a2d940992a34b07dc4a9f10418e5bf449837ef75d366cf4d4a9a3872deb9bf7fbab8faee8d973c5a3affe9ef7eef0f21b152b22c3576cbcb16244f9eacfaff9a7973fb5eee7cfc58fefa1f3f80cbb403ba268e4f5d9b13dd28c5c5245a4abc21c836c3176b15cce7eb6f16cbdfd70804f467a333949bc5a13c4a121e2053d641726bf39eef1174c4cb1bd3476e4aef1e26ab5ce54eb4b6387efa41df70ee9dd5d2294f5bce7febd43fae41aa78304ba7cb0b907dd62accae88956f972d333daca28343aa3b364497e3ec9f2bcb9edb1a4a35efb31f3d1dc55debc74f82c437245b7d73a53d7889cf623e2b411e6361139496de888ac3cfbc5facb62cb7660c574604bacb164e3d6a622632da841da80d5bcb5a539300390674c8ee7a1bce0e478601769a8b174d8d582f661c481bddcff81f98390bf7577299e93d77369435ecff253f797771df7e84711d6330b1f1cd333e7d4ebfd378c1cb1a65bf1139f877f3a7fcc03ddbb7fb8bdff7abaa3c3e80e831695b57fa0c3c0c564f5d6e4e482bb474fb7a933374c18bd2cbbd363be153ba2a3e1eed041c573acb3d6173f50deb1ddb43e0b36470b3a7ec6fad254d96e64be5e10eb003e92d0691517215624a9f68b8d018117738e2830748b31e03fae06b81dce191bbc43038f193323aa78bce53131f313fe5febf03984212a6485f2343c8d4c63d364750ccef278c5127532b6ae8ecfaeab93ed274f9e44c6af1a2c9712252f18430b2af5f5a75704b6bf12c0f65702d8fe0a405bfd8ac96cd2aea89a591c74cda258d42b8a62c9d78849fa5e41dbad9a991185a2a94c57a69a1fb7da1b1b73cf8ae8279085befe879557b73621fcf11a0caf47132bfb5d81839428f6e0f3346fe02079dfe3d7f9f5f7f096fbf096d6536139a64b57e97d2d334da475a6e9ecff66a6c9d855b9f4383fb85e2ee68b8d7d9ca41fde4dfb1a568b2c44629f68b02eb1db21b09193f6e546ce73b9d4ef1605cd572c60a235d3151da874051c92194807f88d5d9101e513e90a05aa5e811618905aac9230339d1a1434ab982175aaaee0a9144d030ae6369ecdad77fe170afe77caddb63542104ec38981c3fbf81c4f03da9dc17b5bce242f1f7b1f1ffb1e3663f37bb74e9b9bc56f719291ca6067126a8b904341bfd1743c03a9fb10744b49eb08740e4779ac423a0a166391ef1ebd2280502b608452850166598500b61501445b21106d8540b41506a2cdd7c5027802e2caa84913d18e02c10e560932c06ceea94c032e054e6e0d96dd19b4dc76147b58140d276bb88b865905ef824fcce4d93cfb69fc21effa34aec375d220b8ee321bd7f1ecd9f804ae9bcdb3715d7373f37518695fd90e239d6c8c745c73b4f8cdce7dc8a41a230d66b321f2a62027ed7c26a906bd4724911965e0310ccc7039c3e790a44e526fc92efbe40219544e5603f951d7fb35350f8a543654d032bb14cca3fd6176e9d0ff7e7629fbffd5ec52d5cdcaff3eb9246698592acd91fb81ec8ef0594dd72405bd69057087878b6de5f501e501450ea80f688ed5d01c2bbc029a835ae7a003a1c73be293c0134173e4ca0acc2065191987e34f9bc68d185e68795adfb46ad526b9dfc081030695af5c099267ac4f571e017e94206457d0efd2553ca3f5fee0c07d2191d24690c8457b5e58975fbdbafac5fc3df3a5fc3d25287f6e35aac6defed5ae6aabb7ffb8eaf9e32755bbfa8eab467d0bab5fe8558d0bbdf98163af6a346c64b53578d1b5daeaa8c6d9a3f6cc47462d61d5c82eaa10554dea5eed7254936c0435bba0665fc148f8c8d73570577ccb58ffc58bd92e760e45a24e3e8880a322ddd690289723ca7ef65463eea98b8da73a229f8df9a56abbd51f6a0f71f85d2576b1220c0c89b04b89ad6ba9450239b8895dac8bcf0cf1b05da72e0fea593a75ee5cbeb88edf272d6dba8a5f3ef8c5a4c04a6bdc66f3a6a61c965655c5fbfe703548a9290605e71914bc21ed064addda0d118606fbb408a70939dce17238b03713f44c742fd4e577be1e6e7ed9b4dbead75685a397f1ee503f5d166e3756d207dff638adfdf784bafa178c7cd3e9f291d0aea30092c8f1c14596a19ea4f838a240cf439cf1712cf92cff95ef31b6450cc1b68fcf34237ee36a088d69fc26e42a0821c27dcfacc49bf1243c116f5e71ee1d7ee9e7aa9ff96518437015a153469d100a8c49ac5c87ebb6c675d03ed965f17b64a0c5c195edf0799af15b9a434185d3811b6ed0b32c9f39341c142ed284a37439da7ef66c3d1854b1f4c0678df49b5f7763bf5e1225fb995b44c53048f1ab0cf11e3b61d99d9d8eec7887b19959f2c627c63904f07348d378e4877cd5793f9df58f9bd8ceafdde4837015f66d7ce52b9656d374b2e966d7aa74bc9d8ce44d1bfefef9177fdf8e1d4bcb9a3e0fae18554e41bf9c2027d93eab2bdca6a2a8505d21514c12f3b59917a10b46d72ca1d86f525ed75849981f49621e29d3c00df1c60f1305760d043b66c051b17053b234959e3c499e3919ec16ee0c5dfaeae5cd621f41604f0174e88bcfff8edf12fd290bac5a34a4d605964d97a3a85d7746592deea0d08a7e9874bfcbecb4f86d25cc2cd6a60a81cdc0ad5330b72455721ffce2c46d224a9ff8e12a70e5f95bd219e0232b3564b334289baddacdb28cfbcf05b5fe5be3be1764f91de5317b326a909ec43380bfe5c6af389fe0ef05d777a5fa2c16498e524c7e8d4611639b8540cbd0f5b74c925f26251a161b2eea4f65a4e220d9a0cfe4751e25765bf0a82ab1889ea535a4f1f7a0bde08a4668a70d0af22bb8e3c9833a801c6928dcde41324579a490c03450ad501cb3c9ef29714b204bccef4e0fe8490636a8139fd9d965a8b1e014f4400a35f632f57e65e3a34d763c58f0e977ded87425c81269c776ee132c62e7829a5c6ff4c68beedc2b10ee334b7e5c8214224561b157a0f1546d60bfb2b13dc07182bedc946aac1615a39800d4ba60ac4d0d05eb64235156973fdc1e4aa32c6e7f689861e00d8e1bfca67e4b8933c48642c55032334f650aeb2436e8d8a9cc3a777186e3d60d2b0e7c86ace191d342f99ed2a471745655d5cd2faaaaa492b3dcc2ffdc3b2d6f16ee44927044c339eec177f1f7f08f2d76dc18539231a614d0d4a70d097cd167127b4a650d479991db2e34e16c202af739f22d66bb4bd518519d14bd61d3e5f4dc5b594d5f88e290558758912766668983a99a26c14bb1e7e64a3f0988a0da7f62f69f46619fcb82552b566c58b663e6c092135364efdfedd60bf95417b1338b6ad6ecb981170ece9e6a224c0d249b30fdc74952f56bd397a4f719eee2fc24e7dc7586f46efaf257227e1d26867cd3f466e32c8af90f3c04ff03873636d3c5e49ea698e00ae90dc62f37e4f9cc91b1e1b46d48b806f63fd5de9879b6fed459c3558444f823cdf6976dbb5d7e73e2cb49bbdbf8d12af3b2d4e0ae26510c35946edfdffd3fff1c03e9ff6fdc75c5c255aff08d579fe197dbaddf39f7d0c7078e9c3afbe6a6578e953e78fa897a764dfce0427c6cedcaef7ec88ffa7854da4a7ff0d718c2ee399ad206fd71af0575689aaa1acbdc55aac96f10a0bed8e3d5598992ffd77b2dd4aeb49f7a379dac16d3f902106a9a478ad0fa4afdb511d2486d8234599bad2d929ed7fcd2062db0d7c2481408f9c32cabb6690abf564bd68add4d629b4560cb056ab5268f05ac09608506e957f080de7db2ee444a5ab53e7068b569e0d007aaedf036f26d30c63ee3377aba8e6ad991c34a0ddb32ea9644b6ee8b0b08a4295f08a304b2a8cbb772a9ff7b410cee103244eac449f2574c9bde230f5d6c6ae03f9f0c8acfdec6d901f1117d027fc6ba419f6c28d1a73b241dec5d948ced862f13b6cea79afc7209f6234dace2002b900d9a2a7c9737a0b843cff71c41679de491c5e3abd2b76202bea921cd7056fc46538062620711686587167f2bec2b5ca71ad7c1fd2b709dd162890cfbaba0589f5df22b2544d624b1c52f4a112b12039d12ee22a3e5a7f458f7c0ce36d12c18dc73c156c45e14a8b5636b2bc9462b0986570faea987eb6ca355c31b186bde7bee7339648bd37eb656e447f6e7db2d25e0c0d3ebc5625ee083d3e64060311c0e07b239cc5687c562160b798d45bcaabd7e5422c426868e74694d35967be286dcbc276f668728677b1e1f58c1fbe7cca43155918eb653a4478c742345b3814e538c559316148b7af81cf1763d3cc28a3c51d196101aeeb0c789c1077ed9cfe08bd582fca16e4f49acc2fcd1d6d87461d5ecd72f1abf3b18c86a64057644d30481a012b3b33c9238611e2fb59cffeebbf375e72f5f3e5fc78ff09d7804ee51877be061fc357ea44edae23e75f4689ddb5d77f4e82977a33d14a7610d5eed43972e0de5e70077fdc6cf85ee05aaf668e5654eabeffc36e83bcd16cd8fc07bb6bacefa5cc3fca8e0384d2ab8187001a7aee7def29d60f959f79b2b84efac6a719d60de45bd6f0077de34643441c828b64459c118d80df72216f0bd45fca6d72d728958a80582012e454c7f1ab391a2667a853f6420083cab8e14fd70156fe04f6fde448e1b2bf1056e3a6af4b9adf0f7248aea5126616a6ef3f73e552750bb2ae420f37a6eaef05a2d0e3f4bda45869cfc5d3a09ef55c2db07ba1ea0863ad5e875a6cfe6b0f811541c24883d58778024baac93129b3948144195dcdb2185411ae568a009d14a2b755a2844502e484f98b14f2f14c61142fcb40439fdec75971fd92de19a137c390db39f1288bcfe5470976c8052d92d1002c05e72005774e98c7fe5779385011021c0de90c106b478b96008e0ad56a4d7bb57d3e7bd7b0575bc2f3b674f422f1a18abadf4e61d1847078c93e07331bfe5751368932714853b9839ca14803ac11e5d3690cdad2e64fd5fc57d097c1445f67f55774f77cfe4989e2393fb222113c21148484234c880215ce186702301b9e452ce1f3701e570e14f3420870271e5e73a2a3a41240944771114e5705102a21b5657148505967595453253f37f55dd73244465f7cfe7f39ffe4c4f4f7775f57bafaa5ebd6f55bdd73eba928548edf92f0d18e8de7fc24716336d541a845754a2d4550aba143f16d1c9d1160985031629a0eb73191611b74afba2a9cf76c856856291a837b8adb6e658440ae953c589148b48a28a452cb6e424731ec82b8d4b4e9272727dc0c43ee72cc00df986cdfd359f60bb416e7bd1d933d808b0642d590210e5a77a5cf40e8e03fc81e3df39f77f4829d941b693d27290cf59ef25b923d06a048ba58b23116db53e6397b7c66db4276f4ddb975a96921e1a1d25442729c9ade352053b9355c135555cdf30329935d84a124d0a1da3cdcb3529f6346cce03da226d264502f0644fe355ab5eb7a2617559d9ea8686556565abdcf3c20f1ca07e6975f0a15e7e070e849333274ee88af7eea53e6a7be1437dd4f6eef5fc0b479d3ef5e959eaedf7e9d9d3a77194670674238f01f5eba1743f6016ac0d391c21518255176742d1fab048509e5acb7484f610b72a65fa88adfc3e8b9eaa6d6d597a7584c96033e90d7a557b8ec2acad26b7821e312d35a7736a1ba6dd317e7eebb3f801f2c1b35bc975bcfd512fc2027431c209f2035928d8d7ace3cc4f3596709b629c9f7dfcd59db6dc22cf06aaedb535dca0977ab07af8385de12ae6a178e8731e006c646ddbd36ee607c7259bf53d33546bfb1ad5f60e93cd69da96915a2b26d4eae3508db83103cca2fc7c1a07874adab7d289b7a7e574cecb4d6d4d834b80c127c12e3732684d14b7dcb7fee99624ea1e1803a29697e466776a7f6745f1718bb4faacb64c4a58ea5f11d511c77dbba84de5c2da4a0e9b9eb56293bedd821d5d16bde05b3b4523fbd055640f0913b42809998eb070b3ad95ce1c87f4b2b928596b4bf5ccd6464e4392de69aec3cea44c9f4d178888907d774404312519cfc5e28a279f5c41eefc30edc927a791127cf0fdfa998faddcf8dd7992cf0964f323a3478fc71f911343fbf61d5851fed4d4c5c6a8ed739fdbabad443a0394017e3808c841c6451439d01876070427ae0bc20f87789be7256142853b9b96cc0cf2ad2e9eadfbb031fc2087999d51461b2f875a9cb6480d3f1cf3e10767689d29221cd99c9666f84102f890cb00b50f3e1ce66c64f94272614cfa44eea78a0af7fc8a0afe818de4d186dcf4e167b1b3de9d4d86e058f22d7e03ea8bb6021aea4b11ebc7602ffe03a80a460ef2af2387baff4fc8014bc0ad5d430eddaaf195f364363ef53e5977b8fa3059f73e3e45669fc75784099e1fb87032d83390cbfd8854e0591f794e7055f84dcf0fc0ed53de4bfc87c232400d031c21d1e6b40cc5cc472419da280d34769b5a9f6c496b13d753d787365667441bfd5ac3fab05a1140c38f6e5768bfc123ddb13f8ebac6c69b82fe77c41a7cf8d5686eb40272ef2d7b9a901b839ca37bbd3a6e9bf3b90d5b9e9fbfee778b7abd583af1d5e26397fe871b1bf5eccc7d07e3e25e6bddfaf1d123676c1f55e4181b13ff87a8a85d9bc695f9d6572e6673b5dd1c110c37d471ba90228a1c6424c962918199205072eaf24a0d39380c01b4a13a628d6238802a4c2c2caef67c73ad9a8ba583acfc1af77261827b255f06f5853d4db4020ad8cb50c00cb4d37b0a50806430f38002c201055000e08a681105d0bb9fa1ab348250808c8a5a460175ff3d0af0558f43d59cf43519862f7d4ce6bd5fad5585819ec15cce87a402e829067ae6d1150bccba2a32c852881c8c00aa439c22e891600090eb070092587cb04b21f7530d593a72fc8eb81555f8fd6a90d6e93964d07b7fd6b8d50da4eb96507f87cd1729a04e2f86861749b26000c6698c8006d5aa0f4408709839936cd06b2107d43803d0555c5700e95d972987c1fefc8770187e0877c321b5e4640d39510b4c9ab91b4087cb63e73e770fd2a45ec6a46e7758f54e4e4075524858912cc8ba80f81b58a745eb47039d840904d03854cb0dafadf5bc0639d31980c64a4ef0b835cdb180698e4108053d45452f4ea98e1379595f8404592a6a19bd08656ab65468ee6cb895d62f754d2ce43a98a117cd9f05fe17b2a780b527cc624f893ba8c7bc2c52b7b27aa66edfe62527aad3318f608be6e35b2074223dde263d98d6e54fd31cb5552a90e368f676a0c749893895596ae9281bf57098727ab63127878ad1b2bd430c5ddfdab919fa30b7936b13226aa2b775eec4d7a61a3786bcd359b946a790a0c364108476857926b6d8d514ec83a02df7376b4e3e26b6465732b125ba99cf2c9d3877eec4a5cfe0aff2d70cfdc3952b7f18ba26bf367088bff225e032ff7efc15cefacaf1c6022e7ffc009c832db0752d1e4fcb657c31809aebb09d1c30de739cff1c927aaebd729cf2adad9002be47a9e505fd8f95d58a748a589c22680b5ee6586d005b8b9ae7d522570780c5d9126011cadcf9b4665454806ec8a605488668f14311e46a420f3a4c9c33cc28d5214b1136ca8a2c4b663f6c01b4527fcd855c5c4a1f5798cb98d267c8c82a2eacc6fb27173338a9396457714ca406647a13e78e29636b3ae74cc36d6af0678f94d4e038f2d382071fc4b71a2bb5fa276e67fcd0d1cb224ee60d7208d57fc1a3970066ea90ec6c11cce8f017b5775ad5e2cf6b2bf8d38d952a5b9aa4a4b64c4b3034e384961b22ca4c581a9a51c5c5d04c1d4533ce5f4633e276f519f0b080e834f18155f010e88c0e4c6744d079b1c89e16331f1e22cb069b728c4118660ec8ce903a29dc196a744a99d7d4b90eac061457618d2e593378f827ce7f07264c17b2954bc512f9194b2bd6ace1b6bdf4ca2b7bf9d31524af42b56c90aad975cf0b4b153b9a2eb4022c23a21a6641062c2f0b6aed0889e889cc465d08b46cab6a7551b10ace107d9d8eda26dfd4070dd23220a392c52f5903c61518596b3c8e5a1ccea8cac7c5a3c70301fc6c9247294241fe6b51a033f53ad96ce92d852386617ea48b6f1d91d49d2d246a2d5acfd5da24a77838a456a9a110868ee1ddd05cd95a803079cc8b0d6443173a0084f18538b43fb17b57c5a716cf875c56e89ee33b5fdcf53216717bf217e27da7e25cc96b5f544cffb2e4f5226854ff04bbfb3dfaee8623de4b62315b179f0016b531a9a7de6ce6cd51a1d1f1725c51a21fa9d0725250adb12656ac8dd8181bed4c88ab8bcdfca63e805d82a274e69ab37d06b63d856116a1af66277b9eb0fc7cd36752ffac3f535313702a20efbd0b8dc0674677b8edf937e8e8ee40e37c28b356accc6ca8c0a1b7ea64133207d009eb6545a752a78f70f2149bd4ff0a367910d435c526eac20fe6f085f192558b6edf5eb40a4ab464fececf3ec7076bbf2507f9f8a1e371e958f766fcf7980d9b7fff626325fe9cd891cfca14e94cc48bac66751fadf39f55d4b3749698bd1da5a5d947239b7d4c7125f8661f538a4a5dc696671f13fcb38f09742a3168f6d1a8d02cb4d9c714938bcf412eb32b459b7d4ca1b38fec2cbd8b79d2414f512e5a51225856466ba4ac0c90e3a14e82895a94a4b80b4eb126ce1abec9eab424cad809f67fcc3a4398b02d019ae5b16bcc68668b1ae87a74150430c3cf64455007cd393eb7962f5dae5a2ede73a9c7fe85072f10e7674b7e5ab66ce71f6af94f36e303a478339935f9d12be4ead764549b8d36dce1d3337b8eed268d6a9be52f88744c760f1b7d9884d642cf18dc8a06380c8610d9ac70bd6d3da3a9d3a75b1d09e0d6f2eb75a6b5cafaf05a8bde6938acab453596e6cd48afeb53156ea0cd486fd06625b3222398019bac3a2fe64588aaeb22b7f7e55d2fee3cbe2794cbf27c68f9b462d7ee8a778897fc0503182d7abde4cbe9155fbc56f26a6fe6146ac45d8176cda702faa361aca7d7bca4e07f5f364ea9ad2180da328dfdd7fcd5e07a3fa697c07613ff0875dc06e593eb084fee19630e35c90992192cb8246d3e521b2e4c70ea139d8a59b5e51466cb2934fc8edf9ecbf62b4f6ad6b5d6ec7513b3ef2ebc76fe7b5056cf939d23c7f3ff4341e24b9ab1a76a2dcde05b48f528d9ac694c118c4d361fd9c5a1c4f7b4997506b31c83428c7258917f4692a18b308b531f13e2c48a39bc4e1fc6cc2f5a67a89114204a9b9bc43eba84011a4d9ebfd6d672adf0584615b5cf2841d40e506d3577b64614f30a153688d4cf1574961c6d81ca1cadd5e538ad2e835068d50857ebb18dd563730c48cb5793efaac6c18e62fe2afcd682774ed42c5bb6ddd9a4fa5ebd4ecee08c3dbb8fbc481ab5de467886d5dc979946983447f2a38b192abaa07a629cce67b131ccf1263b3b63fc29b557d6ac5ad6df43871ce2d4fb0d18ff6ca5136c9896672b879129d4802153b46eb8b1927ccb22d25fe15fe0168365a81ce49ce88a00c2fb400bff4f03d2f35ddc1f728bcbd594929ad2f836a4a4098323d74b5d6eb384d4cf84bfc2cf62738cd406b78868b79e2f0bd51bc468891724148d69d4fd53f5a71452ffb1ff0d3a2939966c5ec7f6b88c86adc53be99ebfb20f772347f6b1fddd79ebf9dd22a2794bd1226631f843a9d5754a69b81194378b86db9aed310ae4ad3bc7a2e2beaec6c6e5d13584242b8bb82fa96f0b9005b4c6207242b40e88d647cba16c15653db3ece90840c7d6da6238fae59fabafe79ce7ceddd977ee1c611f5af2347eec40dd39b03338ef78a6b5383c90690068f752a4eea6928692aae9f9247e2ad2eed0f555cfabe9f9be4dce07724ac23bd5d157ef25399bcda4f404ad42c77c94b4141cd92c2e93948013b1bac4b3894f53e4ddbe4ff6345ca1066afaa3d0247ed3f2ee4b1f1a3371c2a460a7a7e2262e51a5ed74999e1bebb0f8d49d0b527080a7545bf98a03d9d1b1c1ee50094ddda5ccf415c9e861ef9fa50ba200082515304a0fe0e817e21b44060f2ed0b7ccb4e0c3af458de58c958f0fed3d65655d1dbf63d6a6974f7fe09c33b5b06cd2d82dbdde3bc2b92eb80b2fe89ce3e77459bc61c3e22e73c6f759dde7c4b51b9f3cbc8abfd563c8c37db6ac36f427610fe906ee2e7bee7971c4d8a4bcfda90927eefc7c927f727fe78417b654ec4aec5cd52af6ce27f53fc702fd0540ffb7407f348a07fab380fe5f248b11edbba2a4a5b2724a828bbcd80235dc454aa830a374e1c2d2098b16912ff1ea2fbe202b3ed76d0b2223de4dc9e807c409bb9f7d664f254eaadc75fb5cfdeddbf5348e08d026f707da2ca83d9d2fc32d3972fd2ab5bab17583074d5a505727964fd8fda2e7d55f241317738ae7a7b9d3cb16e09beef242fda02382b725326989e7424b38c2e6ef13515b94c9d9fc361172a1ccb7c28ded325d42644115de7a1d4054fb8bae0e05aef6aef8bfba524e2b4a9550d6ad4a6700245550150209c0a60931bb22f35d914945d37abb2215571b3076e253fa4c7fb06a15c76ca3aeae785724d841ab264e77c583596505f3aa05d3caea33ad46b9accafe98b424170fcff0d9571db1aba352c50bc42514b8d031175f658af3b89402058ec272ddaef00257589508a7a4029731df65a4d42880fe0cc002cf6cb29002fadf7a1e1e9474d1d52edfd58e519ce44a3bef4a73c5d0d3946a57a6ab9dcb0a773ca0d00f5ce804b437a777d0c8b7d362ac492029ed8c18d9a59fcb3064247dc4dde9a909e83bf4337f4094c2c28dbef33ab080468d0ac8ccea8ad16466059945b62cb3c880cc2295fdf1296d9ac8ac934b704990091a3232b44a314a60a35689a6eb2e28459dc96308e5c2aa74a2ec121497ae20c410caab7f25c525c2df51d939593934462254c6885611f4c82a625633d5c5db79c14b18739223722b682cc55d872a6834c55dc2a5f2a953cbe977637e56563efd6ec4375e9d21fca931913fb56aebab331a1dc2dfdc9d576de5663ffdc73f3e4dbf03a64e1d005f4fe152baf212f3fcefc474dd0564a72bcaeed565348f7a758112e65378e8852f0f1f61efde2bb36797c7a7976fec3cafd79847337bf6cbebd6e5f1494f2fcb9e7ea6e6c5dfd73cbd71dda60dbaea51ad2c1999e949217a7349f781632c111332a2da65b5cb30e8cdfdbbf61e6bd491d7f130cf87780bb980d3c94cc4d35850724736566401dd837c71df7441317731b36604fe2d32773b99c77dc5cd2136b690f796e729ee1f4fe1af3ccf0b1356b993f8af264c21ff9e420e4fe157b92f4fa16d741b42fa6236ee1a8aacb4670a84dcc53c8bfe6c4f9652980b9b16f3671bb78658711d29dcc6af791b3fe645dbf0a2a74793c2d11bf9f39b7fba554e8ee221e5e4efe44a399e004f2507577aaef0327998cb71afba7c995f45dec2fdc910d2012f276bf05f29427179dcfc20e959e89b11980b8ac56cc9463c67c2f38e561e7ab992b847aff4b8aff2dbf0d75c47cc7bfe45d67a6eb8afabf7e179d206fa6e6cba9ed675f4a8b4e1d63c9623b1428e1b588e1134c3140e32ccc1f356569cac3c535e296db8eafe5f328258c964dc13dfe0d2f8acabcd29c951780e679b2d665304b769e568e2ae7cf9502525c4c299f1622e9c783c6748827bfa5584b94decbe0d204f443be68efc20468a7e53335ab22320533e8566ca6d3a5a597ea6f264c54a4acc69cf5f88991cc6cfe36bd8c98f09d0320b2c22900a2be57947b94a92e271eb9f387a4fdcd33b5951e279f8a26782b4e1df038eea1734cf9b0db5709b480a07dcc96f1cbd45bde0348e96d0dc6935076a8f4a4b6eadf6e7be84dd9b4d6f866b9e09f8225cde0974712f79aeea4642de618ceece7980b623925b4962043feed09cc587b0857c37b930df73555af0e533bb5d5346eca0efde80a78d93d602d243d49489861b157b5a6b7b4e76525e6e343c06f00cb7e5818cc98766f7238d5dbb62beffec4393d3b923495d2bc8c39eefb9505cfd4877011fee3909bfc5857abe27bdb717505a88156859cb685107e122d421397e5c7ee1641c4daed72c9d23adbdbd6567c914d7eecd7f931e458c831f819a8d8c771ac268dca1439e1ff5db199d57e18aca9b894d75e72467450282e05e82fcc877d87268f11c606df98e1190df335fdefe9d9a9f9b5141b94bb3a7317e226dc9d9119220898cd7bc5c7e66413a70d71ff35dbb92c67ec05d067724b9603baee1a23c3f92fe937a1ec642f747481fcf8f5c147ea7a22ba5064a629cc61d74f892c8c8c9cbcde15e3a3467690db98ea341d2c0de0b7fdb0c922ed9e98b2701084a4fdb3ad8288a2d898ddd289a4b0c1510b311900229b8b915afbf86d35f7fdd33e3e8c0eeefedc66e925eb7e0d9eb38825c2749e41ffc97df91d9df7d7ffcc32b6410eeff7ce6a64ecbb6546ce8d3997ce8f9827c80f3b5483eba5799bf566f87258d05ee094d8e0a4b904da1c98ab5b8357b4b04754753e88bba8eb1595c7d98c969e662d6a1a86d62a2b92ec4985970392b8b14dcc8526e8079de24704f20780f73b792e805ca89ee555f241f22b1603e6fb8268101fc7393a83ebec83e3bd2d3a74d5223fc508cd917e88d006d3bc4618a2d4291b2cd68156499b719c4e29800bd84cd6a9a651ee0f8baf0a8776d55e1dbf4a84e8729b53708f367caeae808f1c656c696c7ae8a555840aabb49068aa9f78dd057a574df5bb594f29f6bd549058dc6ea3729d178ff154da61a8d790e636411960543a82c2b8239bcd846e953c963c8dc0878525887b699f475611c258c30aad8d44b72f3f0475c5f0ed592ea4004241ac045b7b4590c2478bae886a7b7016b73b4232ab328b2ad9ca1c446c831197a9428caa909fa5669c51d0282624e758a3a091c199b98e24c35e175a8fdbb19550ada669352eba2e393698897ac2cbafc47a123075a296ba599979be71795afcc838236e9a8dfd26db57847c4d907ac81a2eecfeda7e2d4ca9e076942b1aba53c3cce62a7c2f409d7c71ae7932de32e0d0d70d8d28bc264c5166595153d7d915472ac3e31a5d81ec419638c5583a8b8242728d275a169db22a4e43a634c82ca129b5369c68f3a0299dc5225cef631f2c63bc165a1f1e1e7e1b5e072f1970d5b3d23eed7dda4b3233882f9014acc214e3566240602ed393675b5490ea8b04caa92a884b3b322d96f1e2834952cb88d09ddae86a2a0a925961d3fb8a4cfb0a205dd1eecd4694bb7a32f2f5d7661c2d8d2995326017e2c2aca6a5fe578adb878cae36ff7eeaf1b3be6f71b278ea7112c5aa7d110168307af5bd731b7b0676e67a1db1b6d4dd60cfb0847ebd4e4f0b6db37bc30668cc99cf26e4e4c6cfb7683fba5a7641853fbf65bfdf2809290f8c4758f8cc313c6ae2fa6a12fecf69d8306d2e01703bab7cdc29d3a3aba820de7fe4c17ee6da3fb9c61fcff758409e86391f33bd7d5abaff4add79cebc287f93c515a70ae0bf739d7fda25f9de917fdea20efa8612ddcd482bf1df63bdc11cde14ef7f9c9932711f6cc136e909bba5bc0c94a8789e3118fc1e8eb81b83b0218aa82724cf9130bc2a8b9226b2f2b43ccb9f76eb735c62d3dcf281598c32ba32849e422381a123a972be24ab8c7f0544e6f44469c88127126cac4220d4098cda790bcda6f76e86e91db40592850f63b46d906870983458568d44a84ef2f6519d4a3d086cc3815a5e21cfc301e8e86e33d680f7e13bd89c381461e68e481469ed16849e13dc78fedb84c69c432c2eee33ad19bafbb0dbde2638e7009094743eef8fd95ea357f25f7295611427fc15f8911d6dc4b49ab1b46d585a9d94db8890b93fbf8c2b0494387942a0b0d959bcbf7e86ee7e6e77559b474098bfd79898e1b2123425db18a2a6868658a32c6bc376df31327cefe7bc2bb5daf0d1ebcf5247fc36d2697afb653636f71f92cca59fedb22a74d761f038286f673298347fbdcd63ba103689bb84e626e67618af64e86c7c36e86a921b9fc91658ed4144f0f497afb25d1dab87a47e90b7f3a0fcf0024c0dd62eb28db3a6c066e2b2ed30b5b451d1727f0710639244e4fe3e466812e7367a9afb6cad2a6a8598c53ea77b68d1b7fe2a4e7f71fd1577434aea4abfdd9a8212961d16912a9c5d15a1be6091ea0080e7787f94a1668460d3a1314e18e5c7cacc7944937bf0b449f71b70d04b813ceb017d253df1f6ab5d18ff7029b196fe9c341c3e4bc5e44e35023c03dbeb3a1f07f027c27c286d1a36832eca722fa76d8c7108dce31139d81fd27e8027def156c187d811ae0f822a27185ff896ec17123a2efeea4f91a50075480b8c2a2e261287c66e9fcd960ff098c322f42fe239a12cf983c77b6eaddcebe02e4839802e142d369cad0f9617dc17e6aeb63c07bd65bad1df64373513e9d4bf016c277bd779f77a737ac45aed3fc777fc4f60d814b905f03fccff79da57b7606794be1bbdc5bae1ea96761abf6df19480fcf86fd027a8ddcf6f2c18f0eced5ffef084d4973be970fa46ef096df73ea867b4dc752a6fdd67d1ac5e5f79e2b48944999547b4b69c9b4f8dcc0ffc240fede196c5fadfd96374971f6379e1c28979dff11ad67ff13a9dd63ced5de233e8aee4fce6acd63b9b6f1d7277f9968d22ba5726735abda5f6e41b2f01dfb7f677897b3da75c44f65e6dd122597a15525d23220375baa2bbe63ff2f2b2d52eab90c3ff9d0261b7ead66a9edeb5eeb356dab744f28c5cb7f353594aa776f800bf69f4ab021d00afd54a7b156908feeeb47a3751f2d35a61d9ad54a5ac7a155ef5339d16ae1dea0eb7b9bfd820600ea6704f19d769f292ef486414953adb7fed7740ad9478026a24af7083bb3979c25c009f9885e85ef11c8abfcb7dbec7faeb5fce9d7839e1dd5b40eb49487a6b94b031a443da6dadad7237807f835cd3e6f04e8f2dfac91ea73552969b9ae0fae6dacae95fb6a7ea0e455bd1694434b14effdd527b3de88d59a30524a6eb2d26aa6079a7ec865b6bf19d4a2b576ec8df0df9708f5aabc69cbb84f75aae17ee6d8ace72807aaabff5f73d3fa7bd00ca8fb7f7177f5dd3d90da269a5ebbdf1f5a5e5403dca7dee5883fd76aa6930bef2d5f663b9d0d4852d579c1b696268312d6ce4aef55d7df5badd29e5a787f73fdcfeb904f7ac1926c392d69086880fb4dab6a9d065f61ba426dd533ee5d9ecdec986abf16f3fd525b7b00eb8d12ffbb5c41731f61bda2baaf6ed286d637e99dab835a7a7980a6266d0b033a0847ad500afcb64676948eda005a6887daa38ea813ca42d9a833ca41b9280f75813efe01f4202a42bd50311a8806a1a168041a8946015a9a0888e763c01e2990532be65349a3de030c07a4d41a360172b6231de49e8ea8f7671b1ac31b36199ed40ee9e169ed01f574842d049eda09f054166c61f0f46ca0ae336c46a022072940492e32013579c80c14754116a02a1f5981b207500450f720b20185452812a8ec05b8a918b668a076208a018a07a158a07a288a03ca47a078a07e244a000e4601c61c0d5b124370c9c0cd64e0e363d8281f1d195cc7408311fec5c2c6333e05c6a78ef129323e25c6a7ccf8d4333e65c6a78149540ee250661c86320e65c66118e3309c7168641c2a8c4313e3d0cc38b4300eada8076c11a810361bea095b24e3398af11c8d7aa33ec06d5fd862d9cb74e3d000d8629814e2991412d010d822992c12d130d892d070d89241d7940067543a294c3aa94c3aad9974d29874ec4c3ae94c3a6dd09f61cbd0f0a701bd8b656465b87549e9dcd289c8553a77d66ce49a38b7743a724d2a9d3d0ff6d326cf85fde2b933d1daa993e7c0f1d4b9936720d7b4d2d99066dae489706646e9ec52e49a593a2789ee01ffee9e553a7f1a72cd9e41cfcc995a3a0bb9e62e980d29e74f993d15f6d368fe41c89852c3f5ef57988494a1437a24d1080cecbce04f2330dcced3b9288afe4b4b67ce47698fce9c3e15b563fb2cd895a22e33e74c9a891e9a47afaaebef756ccfb3bd8ab5b1c6bd8abf45d69aa6a0b53803176bd764f88a20699a76177bb27a2e97fdead8fc691cdc958e7e829c7b4189fdc87efba27fc133faa31f60df17fd13f6bd581ebd82f2306bbf021b4318ceae0f0bbabe9ead814d87ba5304e53e1a289b0be94478663dfc26a14f60cf6967ceb2a34fd9799a6303abe7f9ecf81c8b7f428fbe80a30eece82f703d0dea353d3e4fd78b818c3826810bec5f09fa8cfd0e5247242057bba64f7a404a9f6c38482f200f6a448f2137cb2b035a4c0fe09bf773910a5252404a5120274a9b07be8d6c7405b37b082b19df7da3fdf5f12bf43d3cbd20144917d940cd6a44d7e623dd3955f9d1e3e08fef3f9ea61d0fffedbe048743be0befa1d319ada665d4f98e83f268727e74d0ffb98163ae0b428d34564981ffd674904807d03b1cd4a6f1682d7a039dc766dc11cfc44f830c24d0420648fd101a8bc6c1755a671390436d056cc4eb4b9a079dda457fa55a8bcd3b5fa4f133f4cff9c69a58baaffde9fee64ff7550be9bef5a7fbc69fee124bf7449374dfb3745360ff1d4bb702d25dbe2b9d0efd9da5a332b8c6d2d1b9d4abece8e926e7aeb07bd704ddcb01c7702f1d1c83231a11446da1be9cffd142ce375ac8f97a0b3927d07b75b4fd27d0ab708483ae3ae855219d0651a657e108ff5f66801319"     # субсет TTF: zlib -> hex
CIDMAP_HEX = "78daedd1d71708041407e0cf4cd92b334ac80e5919215176255919a7c3f16264656f21225b461965efb267b6ec57ff8d174f395ef0c4ef7bf99d73ef3df7e15e5e5001051552581145bda19837bda5b8124a2aa5b432ca2aa7bc0a2a7a5b259555515535d5bda3869adef59e5ade575b1d757da09efa1a68a891c69af85053cd34f791165a6aa5b5363ed6563bed75f0898e3ae9ec535d7ca6ab6e3ef785ee7ae8a997defae8eb4b5ff95a3fdfe8ef5b030c34c860437c67a861867bd9463cc9ef9fd11ff924473de7fed12222225e8631c61a67bc1f4c30d124934df1a3a9a6996e869966996d8eb9e6996f818516f9c9624b2cf5b36596fbc50a2bfd6a95d5d6586b9df536d8e8379b6cb6c556bffbc336dbedb0d39ffeb2cb6e7becb5cf7e071c74c861471c75ccdffe71dc09279d72da19679d73de05175df2afcbaeb8ea9aeb6eb8e996ffdc76270f8c8888888888888888888888888888888888888888888888888888d7d85df7fe57b9efc153530f73a857daa3c73af852f2"     # CID(=unicode) -> GID, 2 байта BE на CID
GLYPH_W = {32: 651, 33: 821, 34: 942, 35: 1716, 36: 1303, 37: 1946, 38: 1597, 39: 563, 40: 799, 41: 799, 42: 1024, 43: 1716, 44: 651, 45: 739, 46: 651, 47: 690, 48: 1303, 49: 1303, 50: 1303, 51: 1303, 52: 1303, 53: 1303, 54: 1303, 55: 1303, 56: 1303, 57: 1303, 58: 690, 59: 690, 60: 1716, 61: 1716, 62: 1716, 63: 1087, 64: 2048, 65: 1401, 66: 1405, 67: 1430, 68: 1577, 69: 1294, 70: 1178, 71: 1587, 72: 1540, 73: 604, 74: 604, 75: 1343, 76: 1141, 77: 1767, 78: 1532, 79: 1612, 80: 1235, 81: 1612, 82: 1423, 83: 1300, 84: 1251, 85: 1499, 86: 1401, 87: 2025, 88: 1403, 89: 1251, 90: 1403, 91: 799, 92: 690, 93: 799, 94: 1716, 95: 1024, 96: 1024, 97: 1255, 98: 1300, 99: 1126, 100: 1300, 101: 1260, 102: 721, 103: 1300, 104: 1298, 105: 569, 106: 569, 107: 1186, 108: 569, 109: 1995, 110: 1298, 111: 1253, 112: 1300, 113: 1300, 114: 842, 115: 1067, 116: 803, 117: 1298, 118: 1212, 119: 1675, 120: 1212, 121: 1212, 122: 1075, 123: 1303, 124: 690, 125: 1303, 126: 1716, 167: 1024, 171: 1253, 183: 651, 187: 1253, 215: 1716, 1024: 1294, 1025: 1294, 1026: 1610, 1027: 1249, 1028: 1430, 1029: 1300, 1030: 604, 1031: 604, 1032: 604, 1033: 2240, 1034: 2140, 1035: 1610, 1036: 1454, 1037: 1532, 1038: 1248, 1039: 1540, 1040: 1401, 1041: 1405, 1042: 1405, 1043: 1249, 1044: 1600, 1045: 1294, 1046: 2206, 1047: 1313, 1048: 1532, 1049: 1532, 1050: 1454, 1051: 1540, 1052: 1767, 1053: 1540, 1054: 1612, 1055: 1540, 1056: 1235, 1057: 1430, 1058: 1251, 1059: 1248, 1060: 1763, 1061: 1403, 1062: 1590, 1063: 1404, 1064: 2190, 1065: 2240, 1066: 1705, 1067: 1807, 1068: 1405, 1069: 1430, 1070: 2211, 1071: 1423, 1072: 1255, 1073: 1263, 1074: 1207, 1075: 1076, 1076: 1416, 1077: 1260, 1078: 1845, 1079: 1089, 1080: 1331, 1081: 1331, 1082: 1237, 1083: 1309, 1084: 1545, 1085: 1339, 1086: 1253, 1087: 1339, 1088: 1300, 1089: 1126, 1090: 1193, 1091: 1212, 1092: 1751, 1093: 1212, 1094: 1394, 1095: 1210, 1096: 1874, 1097: 1929, 1098: 1447, 1099: 1617, 1100: 1207, 1101: 1124, 1102: 1724, 1103: 1232, 1104: 1260, 1105: 1260, 1106: 1280, 1107: 1076, 1108: 1124, 1109: 1067, 1110: 569, 1111: 569, 1112: 569, 1113: 1848, 1114: 1840, 1115: 1335, 1116: 1237, 1117: 1331, 1118: 1212, 1119: 1339, 8211: 1024, 8212: 2048, 8220: 1061, 8221: 1061, 8230: 2048, 8470: 2130}         # {cp: advance} в единицах UPM
WARRAY = "32 [ 318 ] 33 [ 401 ] 34 [ 460 ] 35 [ 838 ] 36 [ 636 ] 37 [ 950 ] 38 [ 780 ] 39 [ 275 ] 40 [ 390 ] 41 [ 390 ] 42 [ 500 ] 43 [ 838 ] 44 [ 318 ] 45 [ 361 ] 46 [ 318 ] 47 [ 337 ] 48 [ 636 ] 49 [ 636 ] 50 [ 636 ] 51 [ 636 ] 52 [ 636 ] 53 [ 636 ] 54 [ 636 ] 55 [ 636 ] 56 [ 636 ] 57 [ 636 ] 58 [ 337 ] 59 [ 337 ] 60 [ 838 ] 61 [ 838 ] 62 [ 838 ] 63 [ 531 ] 64 [ 1000 ] 65 [ 684 ] 66 [ 686 ] 67 [ 698 ] 68 [ 770 ] 69 [ 632 ] 70 [ 575 ] 71 [ 775 ] 72 [ 752 ] 73 [ 295 ] 74 [ 295 ] 75 [ 656 ] 76 [ 557 ] 77 [ 863 ] 78 [ 748 ] 79 [ 787 ] 80 [ 603 ] 81 [ 787 ] 82 [ 695 ] 83 [ 635 ] 84 [ 611 ] 85 [ 732 ] 86 [ 684 ] 87 [ 989 ] 88 [ 685 ] 89 [ 611 ] 90 [ 685 ] 91 [ 390 ] 92 [ 337 ] 93 [ 390 ] 94 [ 838 ] 95 [ 500 ] 96 [ 500 ] 97 [ 613 ] 98 [ 635 ] 99 [ 550 ] 100 [ 635 ] 101 [ 615 ] 102 [ 352 ] 103 [ 635 ] 104 [ 634 ] 105 [ 278 ] 106 [ 278 ] 107 [ 579 ] 108 [ 278 ] 109 [ 974 ] 110 [ 634 ] 111 [ 612 ] 112 [ 635 ] 113 [ 635 ] 114 [ 411 ] 115 [ 521 ] 116 [ 392 ] 117 [ 634 ] 118 [ 592 ] 119 [ 818 ] 120 [ 592 ] 121 [ 592 ] 122 [ 525 ] 123 [ 636 ] 124 [ 337 ] 125 [ 636 ] 126 [ 838 ] 167 [ 500 ] 171 [ 612 ] 183 [ 318 ] 187 [ 612 ] 215 [ 838 ] 1024 [ 632 ] 1025 [ 632 ] 1026 [ 786 ] 1027 [ 610 ] 1028 [ 698 ] 1029 [ 635 ] 1030 [ 295 ] 1031 [ 295 ] 1032 [ 295 ] 1033 [ 1094 ] 1034 [ 1045 ] 1035 [ 786 ] 1036 [ 710 ] 1037 [ 748 ] 1038 [ 609 ] 1039 [ 752 ] 1040 [ 684 ] 1041 [ 686 ] 1042 [ 686 ] 1043 [ 610 ] 1044 [ 781 ] 1045 [ 632 ] 1046 [ 1077 ] 1047 [ 641 ] 1048 [ 748 ] 1049 [ 748 ] 1050 [ 710 ] 1051 [ 752 ] 1052 [ 863 ] 1053 [ 752 ] 1054 [ 787 ] 1055 [ 752 ] 1056 [ 603 ] 1057 [ 698 ] 1058 [ 611 ] 1059 [ 609 ] 1060 [ 861 ] 1061 [ 685 ] 1062 [ 776 ] 1063 [ 686 ] 1064 [ 1069 ] 1065 [ 1094 ] 1066 [ 833 ] 1067 [ 882 ] 1068 [ 686 ] 1069 [ 698 ] 1070 [ 1080 ] 1071 [ 695 ] 1072 [ 613 ] 1073 [ 617 ] 1074 [ 589 ] 1075 [ 525 ] 1076 [ 691 ] 1077 [ 615 ] 1078 [ 901 ] 1079 [ 532 ] 1080 [ 650 ] 1081 [ 650 ] 1082 [ 604 ] 1083 [ 639 ] 1084 [ 754 ] 1085 [ 654 ] 1086 [ 612 ] 1087 [ 654 ] 1088 [ 635 ] 1089 [ 550 ] 1090 [ 583 ] 1091 [ 592 ] 1092 [ 855 ] 1093 [ 592 ] 1094 [ 681 ] 1095 [ 591 ] 1096 [ 915 ] 1097 [ 942 ] 1098 [ 707 ] 1099 [ 790 ] 1100 [ 589 ] 1101 [ 549 ] 1102 [ 842 ] 1103 [ 602 ] 1104 [ 615 ] 1105 [ 615 ] 1106 [ 625 ] 1107 [ 525 ] 1108 [ 549 ] 1109 [ 521 ] 1110 [ 278 ] 1111 [ 278 ] 1112 [ 278 ] 1113 [ 902 ] 1114 [ 898 ] 1115 [ 652 ] 1116 [ 604 ] 1117 [ 650 ] 1118 [ 592 ] 1119 [ 654 ] 8211 [ 500 ] 8212 [ 1000 ] 8220 [ 518 ] 8221 [ 518 ] 8230 [ 1000 ] 8470 [ 1040 ]"         # "cid [ w ] ..." для /W (1/1000 em)
BFRANGES = [(32, 126), (167, 167), (171, 171), (183, 183), (187, 187), (215, 215), (1024, 1119), (8211, 8212), (8220, 8221), (8230, 8230), (8470, 8470)]       # [(a,b)] тождественное CID->Unicode
UPM = 2048
FONT_BBOX = "-2090 -948 3673 2524"
ASCENT = 1901
DESCENT = -483

def U(cp):
    return round(GLYPH_W.get(cp, GLYPH_W[0x3F]) * 1000 / UPM)

def wtext(s, size):
    return sum(U(ord(c)) for c in s) * size / 1000.0

def hstr(s):
    return ''.join('%04X' % (ord(c) if ord(c) in GLYPH_W else 0x3F) for c in s)

CID_RE = re.compile(r'^FSTEC-([A-Z]+)-(\d+)-(?:(APPENDIX\d-[A-Z]+|MAIN)-)?(\d[\d.]*)-(.+)$')

def control_name(cid):
    m = CID_RE.match(cid)
    if not m:
        return cid, '', ''
    fam, yr, pref, sec, slug = m.groups()
    doc = 'fstec-%s-%s' % (fam.lower(), yr)
    ref = doc
    if pref:
        ref += ' ' + re.sub(r'APPENDIX(\d+)-.*', r'app\1', pref).lower()
    return slug.lower(), '%s §%s' % (ref, sec), doc

KEYMAP = {
    'auditd-conf': 'конфигурация auditd', 'auditd-rules': 'правила auditd', 'check': 'проверка',
    'cmdline': 'командная строка', 'command': 'команда', 'cracklib': 'cracklib', 'cron': 'cron',
    'cron-file': 'файл cron', 'cron-root': 'каталог cron', 'cvtsudoers': 'cvtsudoers',
    'dev': 'устройство', 'directory': 'каталог', 'dpkg': 'dpkg', 'etc': '/etc', 'file': 'файл',
    'home': 'домашний каталог', 'home-base': 'каталог /home', 'home-scan': 'сканирование /home',
    'kernel': 'ядро', 'login-defs': 'login.defs', 'mountinfo': 'mountinfo',
    'observation': 'наблюдение', 'observer': 'наблюдатель', 'owner-authority': 'источник контроля владельца',
    'owner-classification': 'классификация владельца', 'pam': 'PAM', 'parent': 'родительский каталог',
    'parent-stop': 'родительский каталог', 'passwd': '/etc/passwd', 'path': 'путь',
    'pid-population': 'набор процессов', 'population': 'набор объектов', 'proc': '/proc',
    'proc-counter': 'счётчик процессов', 'proc-exe': '/proc/*/exe', 'proc-maps': 'карты памяти процессов',
    'proc-net': '/proc/net', 'proc-population': 'набор процессов', 'proc-root': 'корень /proc',
    'proc-stat': '/proc/stat', 'proc-status': '/proc/*/status', 'pwhistory-conf': 'настройка pwhistory',
    'pwquality': 'pwquality', 'root': 'root', 'run-parts': 'run-parts', 'runtime': 'среда выполнения',
    'scan': 'сканирование', 'shadow': '/etc/shadow', 'sshd-binary': 'бинарный файл sshd',
    'sshd-config': 'конфигурация sshd', 'sshd-effective': 'итоговая конфигурация sshd',
    'sshd-runtime': 'среда выполнения sshd', 'start': 'запуск', 'sudo-policy': 'политика sudo',
    'sysctl': 'sysctl', 'systemd': 'systemd', 'tadduser-conf': 'конфигурация adduser',
    'target': 'объект', 'tauditd-log-space': 'место журнала auditd', 'tgroup': 'группа (проверяемая)',
    'tobserver': 'наблюдатель (проверяемый)', 'tool': 'утилита', 'tpam': 'PAM (проверяемый)',
    'visudo': 'visudo', 'wheel': 'группа wheel'}

CODE = {
    'absent': 'отсутствует', 'missing': 'отсутствует', 'not-found': 'не найден',
    'not-installed': 'не установлен', 'not-executable': 'не исполняемый', 'not-directory': 'не каталог',
    'unreadable': 'нет доступа на чтение', 'read-failed': 'не удалось прочитать',
    'stat-failed': 'не удалось получить атрибуты', 'lstat-failed': 'не удалось получить атрибуты',
    'open-failed': 'не удалось открыть', 'parse-failed': 'не удалось разобрать',
    'query-failed': 'сбой запроса', 'resolve-failed': 'не удалось разрешить путь',
    'resolution-failed': 'не удалось разрешить имя', 'scan-failed': 'сбой сканирования',
    'find-failed': 'сбой поиска', 'find-missing': 'не найден при поиске',
    'list-failed': 'сбой перечисления', 'statvfs-failed': 'не удалось опросить файловую систему',
    'snapshot-failed': 'сбой снимка состояния', 'execution-failed': 'сбой выполнения',
    'identity-failed': 'не удалось определить идентичность', 'auditctl-failed': 'сбой auditctl',
    'sort-failed': 'сбой сортировки', 'device-id-failed': 'не удалось определить устройство',
    'child-stat-failed': 'не удалось проверить вложенный элемент',
    'child-not-found': 'вложенный элемент не найден',
    'mode-read-failed': 'не удалось прочитать права доступа', 'release-query-failed': 'сбой запроса версии',
    'validation-failed': 'не прошла проверку синтаксиса', 'internal-error': 'внутренняя ошибка проверки',
    'internal-reason-missing': 'причина не указана', 'invalid-type': 'недопустимый тип',
    'invalid-bytes': 'недопустимые байты', 'invalid-mode': 'недопустимые права доступа',
    'invalid-path': 'недопустимый путь', 'invalid-line': 'некорректная строка',
    'invalid-record': 'некорректная запись', 'invalid-fields': 'некорректные поля',
    'invalid-output': 'некорректный вывод', 'invalid-value': 'недопустимое значение',
    'invalid-number': 'недопустимое число', 'invalid-name': 'недопустимое имя',
    'invalid-account': 'некорректная учётная запись', 'invalid-arguments': 'некорректные аргументы',
    'invalid-utf': 'повреждённая кодировка', 'invalid-state': 'недопустимое состояние',
    'invalid-target': 'недопустимый объект', 'invalid-directory': 'недопустимый каталог',
    'invalid-permissions': 'недопустимые права', 'invalid-permit-root-login': 'недопустимое PermitRootLogin',
    'invalid-command': 'некорректная команда', 'invalid-directive': 'некорректная директива',
    'symlink': 'символическая ссылка', 'dangling-link': 'битая ссылка', 'hardlink': 'жёсткая ссылка',
    'resolved-symlink': 'разрешённая символическая ссылка', 'readlink-missing': 'ссылка не читается',
    'deleted-path': 'удалён с диска, но занят процессом', 'requires-root': 'требуются права root',
    'untrusted': 'недоверенный источник', 'line-too-long': 'слишком длинная строка',
    'changed-during-check': 'изменился во время проверки', 'empty': 'пусто',
    'empty-file': 'пустой файл', 'empty-output': 'пустой вывод', 'empty-record': 'пустая запись',
    'empty-population': 'набор объектов пуст', 'empty-command': 'пустая команда',
    'empty-observation': 'пустое наблюдение', 'empty-executable-population': 'нет исполняемых объектов',
    'empty-environment': 'пустое окружение', 'no-source': 'источник не задан',
    'conflicting-sources': 'конфликт источников', 'identity-mismatch': 'несовпадение идентичности',
    'mapping-mismatch': 'несовпадение отображения', 'root-unreadable': 'корневой каталог не читается',
    'entry-unreadable': 'запись не читается', 'pseudo-inode': 'псевдо-inode',
    'anonymous-inode': 'анонимный inode', 'outside-root': 'вне корня',
    'outside-scope': 'вне области проверки', 'process-disappeared': 'процесс завершился во время проверки',
    'config-disappeared': 'конфигурация исчезла', 'config-untrusted': 'конфигурация недоверенная',
    'dir-untrusted': 'каталог недоверенный', 'spool-disappeared': 'каталог очереди исчез',
    'spool-untrusted': 'каталог очереди недоверенный', 'population-changed': 'набор объектов изменился',
    'policy-changed': 'политика изменилась', 'resolution-changed': 'разрешение имени изменилось',
    'root-changed': 'корень изменился', 'state-changed': 'состояние изменилось',
    'target-changed': 'объект изменился', 'entry-changed': 'запись изменилась',
    'active-lines': 'есть активные строки', 'include-cycle': 'циклическое включение',
    'include-depth': 'превышена глубина включений', 'include-not-found': 'включаемый файл не найден',
    'relative-path': 'относительный путь', 'nonabsolute-path': 'неабсолютный путь',
    'nonabsolute-command': 'команда без абсолютного пути', 'nonabsolute-entry': 'запись без абсолютного пути',
    'invalid-absolute': 'неабсолютный путь', 'wildcard-command': 'команда с подстановкой',
    'negated-command': 'команда с отрицанием', 'regex-command': 'команда с регулярным выражением',
    'digest-qualified-command': 'команда с дайджестом', 'directory-command': 'каталог указан как команда',
    'runchroot-enabled': 'включён runchroot', 'runchroot-mixed-option': 'смешанная опция runchroot',
    'stderr-output': 'вывод в stderr', 'no-final-newline': 'нет завершающего перевода строки',
    'group-write-ambiguous': 'неоднозначная групповая запись',
    'case-insensitive-user-unsupported': 'пользователь без учёта регистра не поддерживается',
    'pwhistory-position': 'положение модуля pwhistory', 'pwhistory-remember': 'параметр remember pwhistory',
    'pwhistory-skippable': 'pwhistory можно обойти', 'executable-zero-inode': 'нулевой inode',
    'ambiguous-uid': 'неоднозначный uid', 'invalid-field-count': 'некорректное число полей',
    'invalid-mountpoint': 'недопустимая точка монтирования', 'invalid-schedule': 'некорректное расписание',
    'missing-shadow-account': 'нет записи в /etc/shadow', 'missing-modules': 'отсутствуют модули',
    'missing-libraries': 'отсутствуют библиотеки', 'unbalanced-group': 'несбалансированная группа',
    'unresolved-name': 'неразрешённое имя', 'pseudo': 'псевдообъект'}

def _code(c):
    t = CODE.get(c)
    if t is not None:
        return t
    if c.startswith('<'):
        inner = c.strip('<>')
        if inner.endswith('-absent'):
            return inner[:-7].replace('-', ' ') + ' отсутствует'
        return CODE.get(inner, inner)
    for pre in ('include-prefix-', 'ancestor-', 'parent-', 'recheck-', 'repeat-',
                'excluded-', 'include-', 'initial-', 'final-', 'mid-snapshot-', 'mid-'):
        if c.startswith(pre):
            return _code(c[len(pre):])
    if c.endswith('-absent') or c.endswith('-missing') or c.endswith('-not-found'):
        return 'отсутствует'
    if c.endswith('-failed'):
        return 'сбой: ' + c[:-7].replace('-', ' ')
    if c.endswith('-changed'):
        return 'изменился во время проверки'
    if c.endswith('-vanished') or c.endswith('-disappeared'):
        return 'исчез во время проверки'
    if c.endswith('-reappeared'):
        return 'появился вновь во время проверки'
    if c.endswith('-unreadable'):
        return 'нет доступа на чтение'
    if c.endswith('-untrusted'):
        return 'недоверенный источник'
    if c.startswith('invalid-'):
        return 'недопустимо: ' + c[8:].replace('-', ' ')
    if c.startswith('ambiguous-'):
        return 'неоднозначно: ' + c[10:].replace('-', ' ')
    if c.startswith('unsupported-') or c.endswith('-unsupported'):
        return 'неподдерживаемая конструкция'
    if c.startswith('empty-'):
        return 'пусто: ' + c[6:].replace('-', ' ')
    if c.startswith('not-'):
        return 'не ' + c[4:].replace('-', ' ')
    if c.startswith('no-'):
        return 'нет: ' + c[3:].replace('-', ' ')
    if c.startswith('duplicate-'):
        return 'дубликат: ' + c[10:].replace('-', ' ')
    if c.startswith('deleted-'):
        return 'удалён с диска: ' + c[8:].replace('-', ' ')
    if c.endswith('-symlink'):
        return 'символическая ссылка'
    return c

def humanize(v):
    if not v:
        return 'н/д'
    out = []
    for seg in re.split(r'([;,])', v):
        m = re.match(r'^([a-z0-9_./-]+):([a-z0-9_.<>-]+)$', seg)
        if m:
            out.append('%s: %s' % (KEYMAP.get(m.group(1), m.group(1)), _code(m.group(2))))
        elif '=' in seg or not seg.strip():
            out.append(seg)
        else:
            out.append(_code(seg.strip()))
    return ''.join(out)

ACCENT = (0.122, 0.306, 0.475)
GREY = (0.333, 0.333, 0.333)
BLACK = (0.0, 0.0, 0.0)
HDR_FILL = (0.863, 0.902, 0.945)
FILL = {'PASS': (0.776, 0.937, 0.808), 'FAIL': (1.0, 0.780, 0.808),
        'ERROR': (1.0, 0.922, 0.612), 'NOT_FOUND': (0.906, 0.902, 0.902),
        'NOT_APPLICABLE': (0.851, 0.851, 0.851),
        'COMPLIANT': (0.776, 0.937, 0.808), 'NONCOMPLIANT': (1.0, 0.780, 0.808),
        'UNEVALUATED': (1.0, 0.922, 0.612)}
PW, PH, M = 595.0, 842.0, 42.0

class Page:
    def __init__(self):
        self.ops = []
    def rect(self, x, y, w, h, rgb=None, stroke=False):
        if rgb:
            self.ops.append('%.3f %.3f %.3f rg' % rgb)
        self.ops.append('%.2f %.2f %.2f %.2f re %s' % (x, y, w, h, 'S' if stroke else 'f'))
    def line(self, x0, y0, x1, y1, w=0.5):
        self.ops.append('0 0 0 RG %.2f w %.2f %.2f m %.2f %.2f l S' % (w, x0, y0, x1, y1))
    def text(self, x, y, size, s, rgb=BLACK, bold=False):
        tr = '2 Tr %.2f w ' % 0.35 if bold else '0 Tr '
        self.ops.append('BT /F1 %.2f Tf %s%.3f %.3f %.3f rg 1 0 0 1 %.2f %.2f Tm <%s> Tj ET'
                        % (size, tr, rgb[0], rgb[1], rgb[2], x, y, hstr(s)))

def wrap(s, size, maxw):
    # разрывы: перенос строки, затем самая правая точка после ; , или
    # пробела, иначе жёсткий рез
    out = []
    for part in s.split('\n'):
        lines, cur = [], ''
        for ch in part:
            if wtext(cur + ch, size) > maxw and cur:
                p = max(cur.rfind(cut) for cut in (';', ',', ' '))
                if p > 0 and wtext(cur[:p + 1], size) <= maxw:
                    lines.append(cur[:p + 1])
                    cur = cur[p + 1:]
                else:
                    lines.append(cur)
                    cur = ''
            cur += ch
        lines.append(cur)
        out.extend(lines)
    return out or ['']

def build(d):
    p, s, results = d['platform'], d['summary'], d['results']
    policy = d.get('policy_status', 'UNKNOWN')
    pages = [Page()]
    pg = pages[0]
    state = {'y': PH - M - 20}

    def hdr_tbl(widths, header, center=False):
        xs = [M]
        for w in widths[:-1]:
            xs.append(xs[-1] + w)
        rh = 15.0
        pg.rect(M, state['y'] - rh + 4, sum(widths), rh, HDR_FILL)
        for i, htxt in enumerate(header):
            tx = xs[i] + (widths[i] - wtext(htxt, 8.5)) / 2 if center else xs[i] + 3
            pg.text(tx, state['y'] - rh + 8.5, 8.5, htxt, bold=True)
        pg.rect(M, state['y'] - rh + 4, sum(widths), rh, stroke=True)
        for xx in xs[1:]:
            pg.line(xx, state['y'] - rh + 4, xx, state['y'] + 4)
        state['y'] -= rh
        return xs

    def tbl(widths, header, rows, fills=None, sizes=None, ref_col=None, center=False):
        nonlocal pg
        xs = hdr_tbl(widths, header, center)
        for ri, r in enumerate(rows):
            cell_lines = [wrap(str(v), (sizes or {}).get(i, 8.0), widths[i] - 6)
                          for i, v in enumerate(r)]
            rh = max(15.0, max(len(c) for c in cell_lines) * 9.5 + 6)
            if state['y'] - rh < M + 14:
                pg = Page(); pages.append(pg)
                state['y'] = PH - M
                xs = hdr_tbl(widths, header, center)
            for i, cl in enumerate(cell_lines):
                if fills:
                    f = fills(ri, i, r[i])
                    if f:
                        pg.rect(xs[i], state['y'] - rh + 4, widths[i], rh, f)
                sz = (sizes or {}).get(i, 8.0)
                ty = state['y'] + 4 - rh / 2 + 4.75 * (len(cl) - 1) - sz * 0.36
                for li, ln in enumerate(cl):
                    color = GREY if (ref_col is not None and i == ref_col
                                     and li == len(cl) - 1 and len(cl) > 1) else BLACK
                    tx = xs[i] + (widths[i] - wtext(ln, sz)) / 2 if center else xs[i] + 3
                    pg.text(tx, ty, sz, ln, color)
                    ty -= 9.5
            pg.rect(M, state['y'] - rh + 4, sum(widths), rh, stroke=True)
            for xx in xs[1:]:
                pg.line(xx, state['y'] - rh + 4, xx, state['y'] + 4)
            state['y'] -= rh
        state['y'] -= 14

    title = 'Отчёт аудита конфигурации: %s' % (p.get('system') or '?')
    ts = 17.0
    while wtext(title, ts) > PW - 2 * M and ts > 11:
        ts -= 1
    pg.text(M, state['y'], ts, title, ACCENT, bold=True)
    state['y'] -= 15
    stamp = time.strftime('%Y-%m-%d %H:%M:%S %z').rstrip()
    pg.text(M, state['y'], 9, 'SecureLinux-Audit · отчёт SLP-REPORT-V1 · POLICY=%s · %s' % (policy, stamp), GREY)
    state['y'] -= 20

    tbl([300.0, 211.0], ['Итоговый статус', 'POLICY_STATUS'],
        [['Оценка соответствия требованиям ФСТЭК', policy]],
        fills=lambda ri, i, v: FILL.get(v) if i == 1 else None)

    pg.text(M, state['y'], 12, 'Система', ACCENT, bold=True); state['y'] -= 10
    rows = [[k, p.get(key) or 'н/д'] for k, key in
            [('SYSTEM', 'system'), ('PLATFORM', 'platform_id'), ('ENVIRONMENT', 'environment_id'),
             ('PROFILE', 'profile'), ('TYPE', 'type'), ('ARCH', 'arch'), ('SUPPORT', 'support')]]
    tbl([110.0, 401.0], ['Поле', 'Значение'], rows,
        fills=lambda ri, i, v: FILL['FAIL'] if (i == 1 and rows[ri][0] == 'SUPPORT' and v == 'UNSUPPORTED') else None)

    pg.text(M, state['y'], 12, 'Сводка', ACCENT, bold=True); state['y'] -= 10
    order = ['total', 'pass', 'fail', 'not_found', 'not_applicable', 'error']
    fm = {1: FILL['PASS'], 2: FILL['FAIL'], 3: FILL['NOT_FOUND'], 4: FILL['NOT_APPLICABLE'], 5: FILL['ERROR']}
    tbl([85.0] * 6, ['Всего', 'PASS', 'FAIL', 'NOT_FOUND', 'NOT_APPLICABLE', 'ERROR'],
        [[str(s.get(k, 0)) for k in order]], fills=lambda ri, i, v: fm.get(i), center=True)

    DOCS = {
        'fstec-linux-2022': '«Рекомендации по безопасной настройке операционных систем Linux», методический документ ФСТЭК России, утверждён 25.12.2022',
        'fstec-logging-2025': '«Рекомендации по базовой настройке регистрации событий безопасности», ФСТЭК России, 2025 (app2: приложение 2, ОС Linux)',
        'fstec-configuration-2026': '«Рекомендации по устранению типовых ошибок конфигурации (настройки) общесистемного и прикладного программного обеспечения», ФСТЭК России, 2026',
    }
    crows, dockeys = [], []
    for i, r in enumerate(results, 1):
        name, ref, doc = control_name(r.get('control_id', ''))
        if doc and doc not in dockeys:
            dockeys.append(doc)
        crows.append([str(i), name + ('\n' + ref if ref else ''),
                      r.get('result', ''), humanize(r.get('value', '') or '')])

    pg.text(M, state['y'], 12, 'Документы требований', ACCENT, bold=True); state['y'] -= 10
    pg.text(M, state['y'], 8,
            'В колонке «Контроль» вторая строка: ссылка на пункт требования: «документ §пункт».', GREY)
    state['y'] -= 11
    tbl([150.0, 361.0], ['Документ (ключ ссылки)', 'Название'],
        [[dk, DOCS.get(dk, dk)] for dk in dockeys])

    pg.text(M, state['y'], 12, 'Контроли (%d)' % len(results), ACCENT, bold=True); state['y'] -= 10
    tbl([28.0, 200.0, 82.0, 201.0], ['№', 'Контроль', 'Статус', 'Наблюдение'],
        crows, fills=lambda ri, i, v: FILL.get(v) if i == 2 else None,
        sizes={3: 7.5}, ref_col=1)

    for i, q in enumerate(pages):
        q.text(M, 20, 7.5, 'SecureLinux-Audit · SLP-REPORT-V1 · стр. %d/%d' % (i + 1, len(pages)), GREY)
    return pages

def emit(pages):
    n = len(pages)
    fontfile_id = 3 + n * 2
    cidmap_id, fontdesc_id, cidfont_id, font_id, touni_id = (fontfile_id + 1, fontfile_id + 2,
                                                            fontfile_id + 3, fontfile_id + 4,
                                                            fontfile_id + 5)
    info_id = fontfile_id + 6
    objs = [None] * (info_id + 1)
    kids = ' '.join('%d 0 R' % (3 + i * 2) for i in range(n))
    objs[1] = '<< /Type /Catalog /Pages 2 0 R >>'
    objs[2] = '<< /Type /Pages /Kids [%s] /Count %d >>' % (kids, n)
    for i, pg in enumerate(pages):
        body = '\n'.join(pg.ops)
        objs[3 + i * 2] = ('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] '
                           '/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>'
                           % (PW, PH, font_id, 4 + i * 2))
        objs[4 + i * 2] = '<< /Length %d >>\nstream\n%s\nendstream' % (len(body), body)
    ttf_len = len(bytes.fromhex(FONT_HEX))
    objs[fontfile_id] = ('<< /Length %d /Length1 %d /Filter [ /ASCIIHexDecode /FlateDecode ] >>\n'
                         'stream\n%s\nendstream' % (len(FONT_HEX), ttf_len, FONT_HEX))
    objs[cidmap_id] = ('<< /Length %d /Filter [ /ASCIIHexDecode /FlateDecode ] >>\n'
                       'stream\n%s\nendstream' % (len(CIDMAP_HEX), CIDMAP_HEX))
    objs[fontdesc_id] = ('<< /Type /FontDescriptor /FontName /SLPFont /Flags 4 '
                         '/FontBBox [ %s ] /ItalicAngle 0 /Ascent %s /Descent %s '
                         '/CapHeight %s /StemV 80 /FontFile2 %d 0 R >>'
                         % (FONT_BBOX, ASCENT, DESCENT, ASCENT, fontfile_id))
    objs[cidfont_id] = ('<< /Type /Font /Subtype /CIDFontType2 /BaseFont /SLPFont '
                        '/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> '
                        '/FontDescriptor %d 0 R /CIDToGIDMap %d 0 R /DW 1000 /W [ %s ] >>'
                        % (fontdesc_id, cidmap_id, WARRAY))
    objs[font_id] = ('<< /Type /Font /Subtype /Type0 /BaseFont /SLPFont /Encoding /Identity-H '
                     '/DescendantFonts [ %d 0 R ] /ToUnicode %d 0 R >>' % (cidfont_id, touni_id))
    touni = ('/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n'
             '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n'
             '/CMapName /SLP-UCS def /CMapType 2 def\n'
             '1 begincodespacerange <0000> <FFFF> endcodespacerange\n'
             '%d beginbfrange\n' % len(BFRANGES))
    for a, b in BFRANGES:
        touni += '<%04X> <%04X> <%04X>\n' % (a, b, a)
    touni += 'endbfrange\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend'
    objs[touni_id] = '<< /Length %d >>\nstream\n%s\nendstream' % (len(touni), touni)
    objs[info_id] = ('<< /Producer (securelinux-audit.sh --format pdf) '
                     '/Title (SLP-REPORT-V1 audit report) >>')

    out = '%PDF-1.4\n%SLP-REPORT-PDF\n'
    offs = [0]
    for i in range(1, len(objs)):
        offs.append(len(out))
        out += '%d 0 obj\n%s\nendobj\n' % (i, objs[i])
    xpos = len(out)
    out += 'xref\n0 %d\n' % len(objs)
    out += '0000000000 65535 f \n'
    for i in range(1, len(objs)):
        out += '%010d 00000 n \n' % offs[i]
    out += ('trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\n'
            'startxref\n%d\n%%%%EOF\n' % (len(objs), info_id, xpos))
    return out

def main():
    d = json.loads(os.environ['SLP_REPORT_JSON'])
    if d.get('schema') != 'SLP-REPORT-V1':
        sys.stderr.write('REASON=schema\n')
        return 1
    sys.stdout.write(emit(build(d)))
    return 0

sys.exit(main())
SLP_PDF_REPORT_PY
}

slp_run_check() {
  local _slp_format=$1 _slp_failed_only=$2 _slp_title=${3:-CHECK} _slp_out _slp_render_rc
  local SLP_STDOUT_TTY=0
  slp_target_preflight || return $?
  slp_collect_policy || return $?
  case "$_slp_format" in
    pretty|raw|json|pdf) ;;
    *) return 2 ;;
  esac
  # Вывод собирается целиком и пишется одной командой: сбой любой его части и сбой записи:
  # код 1, а не код итога POLICY. Внутри $( … ) запись идёт в канал, который
  # этот же процесс читает до конца; точка в конце сохраняет конечные переводы строки и проверяется.
  # Раскладка pretty: по stdout этого вызова (SLP_STDOUT_TTY локальна для вызова).
  if [[ -t 1 ]]; then
    SLP_STDOUT_TTY=1
  fi
  _slp_out=$(
    case "$_slp_format" in
      pretty) slp_render_pretty "$_slp_failed_only" "$_slp_title" ;;
      raw) slp_render_raw "$_slp_failed_only" ;;
      json) slp_render_json "$_slp_failed_only" ;;
      pdf) slp_render_pdf "$_slp_failed_only" ;;
    esac
    _slp_render_rc=$?
    printf '.' || exit 1
    exit "$_slp_render_rc"
  )
  _slp_render_rc=$?
  [[ $_slp_out == *. ]] || return 1
  # SIGPIPE игнорируется только в подоболочке записи: канал с закрытым читателем даёт код 1, а не 141.
  ( trap '' PIPE; printf '%s' "${_slp_out%.}" ) || return 1
  (( _slp_render_rc == 0 )) || return 1
  return "$SLP_POLICY_RC"
}

# Ошибка вызова: одна строка USAGE_ERROR в stderr, stdout пуст, код 2.
slp_usage_error() {
  printf 'USAGE_ERROR: %s. Справка: --help\n' "$1" >&2
  return 2
}

# Аргумент вызова печатается, только если он из безопасного набора байтов ASCII
# (LC_ALL=C: диапазоны и {1,64}: по байтам в любой локали).
slp_usage_arg() {
  local LC_ALL=C
  if [[ $1 =~ ^[A-Za-z0-9._,=/:+-]{1,64}$ ]]; then
    printf '%s' "$1"
  else
    printf '%s' '(недопустимое значение)'
  fi
}

slp_usage_unknown() {
  case "$2" in
    --failed|--format|--format=*) slp_usage_error "ключ ${2%%=*} допускается только с --check" ;;
    --layer|--layer=*) slp_usage_error "ключ --layer допускается только с --check" ;;
    *) slp_usage_error "неизвестный аргумент $(slp_usage_arg "$2")${1:+ для $1}" ;;
  esac
}

slp_main() {
  local _slp_format=pretty _slp_failed_only=0 _slp_layer=fstec-core _slp_format_seen=0 _slp_layer_seen=0
  # Справочный вывод: одной командой (slp_emit_output): сбой записи: код 1.
  if (( $# == 0 )); then
    slp_emit_output slp_help || return 1
    return 0
  fi
  case "$1" in
    --help)
      (( $# == 1 )) || { slp_usage_error "ключ $1 не принимает аргументов"; return; }
      slp_emit_output slp_help || return 1
      return 0
      ;;
    --version)
      (( $# == 1 )) || { slp_usage_error "ключ $1 не принимает аргументов"; return; }
      slp_emit_output slp_version || return 1
      return 0
      ;;
    --build-info)
      (( $# == 1 )) || { slp_usage_error "ключ $1 не принимает аргументов"; return; }
      slp_emit_output slp_build_info || return 1
      return 0
      ;;
    --list)
      (( $# == 1 )) || { slp_usage_error "ключ $1 не принимает аргументов"; return; }
      slp_emit_output slp_list || return 1
      return 0
      ;;
    --provenance)
      if (( $# == 1 )); then
        slp_emit_output slp_provenance_all || return 1
      elif (( $# == 2 )); then
        # Код 2: контроль не найден (без вывода); сбой записи: код 1.
        slp_emit_output slp_provenance_one "$2"
        case $? in
          0) ;;
          2) slp_usage_error "контроль $(slp_usage_arg "$2") не найден"; return ;;
          *) return 1 ;;
        esac
      else
        slp_usage_error 'ключ --provenance принимает не более одного id'
        return
      fi
      return 0
      ;;
    --check)
      shift
      while (( $# > 0 )); do
        case "$1" in
          --layer|--layer=*)
            (( _slp_layer_seen == 0 )) || { slp_usage_error 'ключ --layer указан дважды'; return; }
            _slp_layer_seen=1
            if [[ $1 == --layer ]]; then
              shift
              (( $# > 0 )) || { slp_usage_error 'ключ --layer требует значение: fstec-core или recommended'; return; }
              _slp_layer=$1
            else
              _slp_layer=${1#--layer=}
            fi
            case "$_slp_layer" in fstec-core|recommended) ;; *) slp_usage_error 'недопустимое значение --layer: fstec-core или recommended'; return ;; esac
            ;;
          --failed)
            (( _slp_failed_only == 0 )) || { slp_usage_error 'ключ --failed указан дважды'; return; }
            _slp_failed_only=1
            ;;
          --format)
            (( _slp_format_seen == 0 )) || { slp_usage_error 'ключ --format указан дважды'; return; }
            _slp_format_seen=1
            shift
            (( $# > 0 )) || { slp_usage_error 'ключ --format требует значение: pretty, raw, json или pdf'; return; }
            case "$1" in pretty|raw|json|pdf) _slp_format=$1 ;; *) slp_usage_error 'недопустимое значение --format: pretty, raw, json или pdf'; return ;; esac
            ;;
          --format=*)
            (( _slp_format_seen == 0 )) || { slp_usage_error 'ключ --format указан дважды'; return; }
            _slp_format_seen=1
            _slp_format=${1#--format=}
            case "$_slp_format" in pretty|raw|json|pdf) ;; *) slp_usage_error 'недопустимое значение --format: pretty, raw, json или pdf'; return ;; esac
            ;;
          *) slp_usage_unknown --check "$1"; return ;;
        esac
        shift
      done
      SLP_LAYER=$_slp_layer
      slp_run_check "$_slp_format" "$_slp_failed_only" CHECK
      return $?
      ;;
    *)
      slp_usage_unknown '' "$1"
      return
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  slp_main "$@"
  exit $?
fi
