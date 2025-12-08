#!/usr/bin/env bash

read -p "Enter account_id: " ACCOUNT_ID

sqlite3 auth.db "INSERT INTO account_roles (account_id, is_admin) VALUES ('${ACCOUNT_ID}', 1) ON CONFLICT(account_id) DO UPDATE SET is_admin = 1;"
