# OpenIM Electron Demo

This project is a secondary development based on the `open-im-sdk` / OpenIM Electron demo.  
The goal is to keep the existing IM capability and add client-side security enhancements on top of it, with the current focus on an E2EE prototype.

## Project Overview

- Base project: OpenIM Electron demo
- Development direction: client-side security hardening
- Current focus: end-to-end encrypted chat flow for text messages
- Core principle: keep encryption logic in the renderer/client side and avoid changes to the OpenIM SDK or server

## Progress Plan

1. Baseline integration
   - Reuse the existing OpenIM login, conversation, and message flow
   - Keep the current UI and interaction model stable

2. E2EE prototype
   - Add client-side message encryption and decryption
   - Standardize secure payload format
   - Add local sensitive-word filtering before sending

3. Security UI
   - Show encrypted-session status in the chat header
   - Add clear feedback for blocked or failed secure messages

4. Hardening and extension
   - Improve key handling and session management
   - Expand support to more message types if needed
   - Add optional protections such as screen-capture prevention or burn-after-read

## Notes

- This repository is an application-level enhancement project, not a fork of the OpenIM SDK itself.
- The current implementation is designed for prototype and coursework scenarios first, then iterative hardening later.
