#!/usr/bin/env bash
git add .
git commit --allow-empty-message -m "$1"
git push
