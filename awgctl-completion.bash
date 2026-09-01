_awgctl_complete() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "${COMP_WORDS[1]:-}" in
    client)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W 'list add show edit import export qr revoke rotate expire' -- "$cur") )
      elif [[ ${COMP_WORDS[2]:-} == edit && $COMP_CWORD -ge 4 ]]; then
        COMPREPLY=( $(compgen -W '--owner --device --expires --mark-distributed --dry-run --json' -- "$cur") )
      elif [[ ${COMP_WORDS[2]:-} == expire && $COMP_CWORD -ge 3 ]]; then
        COMPREPLY=( $(compgen -W '--dry-run --json' -- "$cur") )
      fi
      ;;
    config)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W 'show set' -- "$cur") )
      elif [[ $COMP_CWORD -eq 3 && ${COMP_WORDS[2]} == set ]]; then
        COMPREPLY=( $(compgen -W 'endpoint dns mtu listen-port' -- "$cur") )
      fi
      ;;
    backup)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W 'list verify' -- "$cur") )
      fi
      ;;
    update)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W 'check apply' -- "$cur") )
      fi
      ;;
    obfuscation)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=( $(compgen -W 'prepare activate confirm rollback show' -- "$cur") )
      elif [[ ${COMP_WORDS[2]:-} == prepare && $COMP_CWORD -ge 3 ]]; then
        COMPREPLY=( $(compgen -W '--mode --profile --client --dry-run --json' -- "$cur") )
      elif [[ ${COMP_WORDS[2]:-} == activate && $COMP_CWORD -ge 3 ]]; then
        COMPREPLY=( $(compgen -W '--ingress-ready --timeout --json' -- "$cur") )
      elif [[ ${COMP_WORDS[2]:-} =~ ^(confirm|rollback|show)$ && $COMP_CWORD -ge 3 ]]; then
        COMPREPLY=( $(compgen -W '--json' -- "$cur") )
      fi
      ;;
    *)
      if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W 'status health check start stop restart reload client config backup restore diagnose self-test update obfuscation aws-rule version' -- "$cur") )
      fi
      ;;
  esac
}
complete -F _awgctl_complete awgctl
