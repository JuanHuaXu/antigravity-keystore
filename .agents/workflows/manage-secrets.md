---
description: How to securely manage secrets and API tokens using the local keystore.
---

# Secure Secrets Management Workflow

Follow these steps to store, retrieve, or update sensitive information (API keys, passwords, tokens) without leaking them into logs or source code.

## 1. Store a New Secret
When you need to persist a new sensitive value (e.g., a newly generated API key):
// turbo
1. Use the `run_command` tool with the local `secrets.sh` script:
   ```bash
   ./secrets.sh set "SECRET_NAME" "SECRET_VALUE"
   ```
2. Confirm the secret was stored by checking the output for "Secret 'SECRET_NAME' set successfully."

## 2. Retrieve a Secret
When a script or command requires a secret to run:
// turbo
1. Fetch the secret value using `run_command`:
   ```bash
   ./secrets.sh get "SECRET_NAME"
   ```
2. Capture the output. Use this value **only temporarily** in memory or as an environment variable for the immediate task.

## 3. Injecting Secrets into Sub-commands
To run a command that requires a secret (e.g., calling an external API):
// turbo
1. Retrieve the secret: `VALUE=$(./secrets.sh get "SECRET_NAME")`
2. Run the target command with the secret as an environment variable:
   ```bash
   SECRET_ENV_VAR=$VALUE command_to_run
   ```
3. **Crucial**: Never echo the secret to any log or file.

## 4. Listing Available Secrets
To see what secrets are currently managed:
// turbo
1. ` ./secrets.sh list `
2. This only lists the names (keys), never the values.

## Safety Rules
- **NEVER** commit `.keystore.key` or `.keystore.data` to git. (The `.gitignore` should already handle this.)
- **NEVER** print secrets directly to the conversation or terminal.
- If you're unsure if a value should be in the keystore, store it there.
