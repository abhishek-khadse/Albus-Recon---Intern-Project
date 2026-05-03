#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Run Uvicorn server with auto-reload
uvicorn main:app --reload
