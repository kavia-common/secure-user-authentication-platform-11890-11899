#!/bin/bash
cd /home/kavia/workspace/code-generation/secure-user-authentication-platform-11890-11899/supabase_auth_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

