# VaultX — Password Manager

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/aliuzair1/VaultX-Password-Manager)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![Languages](https://img.shields.io/badge/JS%20%26%20Python-Frontend%20%2F%20Backend-orange)](https://github.com/aliuzair1/VaultX-Password-Manager)
[![Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://vault-x-password-manager.vercel.app/index.html)

A secure, easy-to-use password manager built with a simple web frontend and a Flask backend, backed by PostgreSQL (Supabase). VaultX helps users safely store, manage, and retrieve credentials for services in a single encrypted vault.

## Demo
Live demo: https://vault-x-password-manager.vercel.app/index.html

Sample credentials:
- Username: `admin`
- Password: `admin123`

---

## Table of Contents

- [Description](#description)
- [Tech Stack](#tech-stack)
- [Key Features](#key-features)
- [Project Structure (typical layout)](#project-structure-typical-layout)
- [Architecture & Deployment](#architecture--deployment)
- [Getting Started (Local Development)](#getting-started-local-development)

## Description

VaultX is a minimal, secure password manager web application. It allows users to sign in and store service credentials (username + password) in a vault that can be managed through a web UI. The project demonstrates full-stack development using a static frontend (HTML/CSS/JavaScript), a Python Flask REST API backend, and PostgreSQL database hosted on Supabase. It is deployed with Vercel (frontend) and Railway (backend).

Motivation: to provide a lightweight, self-hostable password manager to demonstrate secure CRUD flows, API design, and modern deployment practices for portfolios and interviews.

Why useful: recruiters and employers can review the implementation of security patterns, REST design, deployment pipelines, and ability to work across frontend and backend stacks.

## Tech Stack

- Frontend
  - HTML, CSS, Vanilla JavaScript
  - Static site deployed on Vercel
- Backend
  - Python, Flask (REST API)
  - Hosted on Railway
- Database
  - PostgreSQL (hosted via Supabase)
- Dev / Deployment
  - Vercel (frontend deployment)
  - Railway (backend deployment)
  - Supabase (database)

## Key Features

- User authentication (login)
- Vault CRUD: Create, Read, Update, Delete credentials
- Secure storage pattern (server-side storage in PostgreSQL with bcrypt encryption)
- Search/filter saved credentials
- Password visibility toggle and strength meter in UI
- Password generator
- Responsive UI for desktop and mobile
- Deployed full-stack demo (Vercel + Railway + Supabase)
- Clean, recruiter-friendly code organization showing both frontend and backend skills


## Project Structure (typical layout)

Your repo may follow a structure similar to:

- /frontend or root
  - index.html
  - assets/
  - css/
  - js/
- /backend or server
  - app.py (Flask app)
  - requirements.txt
  - routes/ or blueprints/
  - models/ or db.py
  - migrations/ (optional)
- README.md
- .env.example
- Procfile (for Railway)
- deployment configs (vercel.json, etc.)

Adjust paths above to match the actual repo layout.

## Architecture & Deployment

High-level flow:
- User interacts with static frontend (HTML/CSS/JS) deployed on Vercel.
- Frontend calls the Flask REST API hosted on Railway.
- Flask API reads/writes credential data to PostgreSQL hosted via Supabase.

Deployment used in this project:
- Frontend: Vercel (static site)
- Backend: Railway (Flask service)
- Database: Supabase (PostgreSQL)

This ensures separation of concerns and scalable hosting for each layer.
