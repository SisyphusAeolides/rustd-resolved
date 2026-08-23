#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Publish one evidence commit without losing concurrent certification vouchers.
set -Eeuo pipefail

branch=${1:-main}
attempt=1
while ((attempt <= 10)); do
    if git push origin "HEAD:${branch}"; then
        exit 0
    fi
    git fetch origin "$branch"
    git rebase "origin/${branch}"
    attempt=$((attempt + 1))
done

echo "certification voucher push did not converge after 10 attempts" >&2
exit 1
