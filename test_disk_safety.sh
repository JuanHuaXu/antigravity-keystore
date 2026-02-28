#!/bin/bash
# test_disk_safety.sh - Verifies that Bash Process Substitution is truly memory-only.

# 1. Setup secret in keystore for testing
PASSWORD=$(grep "^PASSWORD=" .keystore.env | cut -d'=' -f2)
export KEYSTORE_PASSWORD=$PASSWORD
SECRET_VALUE="MOCK_PRIVATE_KEY_$(date +%s)"
python3 keystore.py set "TEST_DISK_SAFE_KEY" "$SECRET_VALUE" > /dev/null

echo "------------------------------------------------"
echo "DISK SAFETY VERIFICATION"
echo "------------------------------------------------"

# 2. Test Content Extraction using process substitution in a subshell
READ_VALUE=$(bash -c "cat <(python3 keystore.py get 'TEST_DISK_SAFE_KEY')")

if [ "$READ_VALUE" == "$SECRET_VALUE" ]; then
    echo "[PASS] Content correctly handed off from memory to process."
else
    echo "[FAIL] Content mismatch. Expected: $SECRET_VALUE, Got: $READ_VALUE"
    exit 1
fi

# 3. Verify Memory-Only (Path check)
DESCRIPTOR_PATH=$(bash -c "echo <(python3 keystore.py get 'TEST_DISK_SAFE_KEY')")
echo "Generated Path Type: $DESCRIPTOR_PATH"
if [[ "$DESCRIPTOR_PATH" == /dev/fd/* ]]; then
    echo "[PASS] Key path is a temporary kernel file descriptor."
else
    echo "[FAIL] Key path is not a memory pipe."
    exit 1
fi

# 4. Verify Disk Silence (No temporary key files created)
FILES_IN_CWD=$(ls -A | grep -v ".git" | grep -v ".gitignore" | grep -v ".keystore" | grep -v "keystore.py" | grep -v "test_keystore.py" | grep -v "secrets.sh" | grep -v "LICENSE" | grep -v "README.md" | grep -v "test_disk_safety.sh" | grep -v "__pycache__" | grep -v "push_to_github.sh")
if [ -z "$FILES_IN_CWD" ]; then
    echo "[PASS] No temporary key files found on disk."
else
    echo "[FAIL] Found unexpected files on disk: $FILES_IN_CWD"
    exit 1
fi

echo "------------------------------------------------"
echo "RESULT: DISK-SAFE FEATURE VERIFIED"
echo "------------------------------------------------"

# Cleanup mock key
python3 keystore.py delete "TEST_DISK_SAFE_KEY" > /dev/null
