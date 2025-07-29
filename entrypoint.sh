#!/bin/sh

# Execute gunicorn with the constructed bind address
# "$@" passes any arguments provided by the CMD instruction in the Dockerfile
# 'exec' ensures that gunicorn replaces the shell script as PID 1,
# allowing proper signal handling (e.g., SIGTERM)
exec gunicorn -b "$HOST:$PORT" "$@"
