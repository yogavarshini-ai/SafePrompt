# SafePrompt front end

React 19 + Vite + Tailwind CSS 4. This is the user interface for the SafePrompt Enterprise AI Security Gateway: sign-in, a chat that masks sensitive values before they leave the network, and role-based views for administrators, managers and workers.

It runs on its own with a built-in mock backend (`src/services`), so you can demo everything before the real backend is connected.

## Quick start

```bash
npm install
npm run dev      # http://localhost:5173
npm run lint     # oxlint
npm run build    # production build into dist/
```

No new dependencies were added: `package.json` and `package-lock.json` are unchanged from the scaffold.

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@123` |
| Manager | `manager` | `Manager@123` |
| Worker | `worker` | `Worker@123` |

These are demo-only, synthetic accounts. The login page also lets you click an account to fill the form.

## What each role can do

| | Administrator | Manager | Worker |
|---|---|---|---|
| Chat with the AI | Yes | Yes | Yes |
| Own chat history | Yes, unmasked | Yes, as sent to the AI | Yes, as sent to the AI |
| Prompts typed by workers | Yes, unmasked | Yes, masked | No |
| AI replies of other people | Yes, with real values restored | No | No |
| What workers accessed (activity) | Yes | Yes | No |
| All chats from every account | Yes | No | No |
| All backend accounts, enable or disable | Yes | No | No |
| Audit log | Yes | No | No |
| Flag a prompt for review | Yes | Yes (workers' prompts only) | No |

The administrator can switch any entry between the original text and the masked view that the AI service received. Managers and workers never receive original values in the browser at all.

## How access control works

1. `src/config/permissions.js` is the single permission table. The UI reads it.
2. `src/config/routes.js` builds each role's menu from that table, and `App.jsx` redirects any page the role may not open (for example `#/audit` as a worker).
3. `src/services/api.js` re-checks the permission on **every call**, looks the user up again instead of trusting the role sent by the browser, and shapes each record for the viewer (`project()`), so fields a role may not see are never returned.

Hiding a button is not security. Step 3 is what the real backend has to do, because anything running in a browser can be edited.

## Project structure

```
src/
  main.jsx, App.jsx          entry point, route guard and layout
  auth/                      AuthProvider, useAuth, context
  config/                    permissions, routes, audit action labels
  components/                Layout, ChatRecord, RedactedText, badges, state messages
  pages/                     Login, Chat, History, Team, AllChats, Accounts, Audit
  services/
    api.js                   mock backend: the contract the real backend replaces
    gateway.js               mock detection, masking, policy checks and AI reply
    storage.js               localStorage helper (demo data only)
  data/                      demo users and synthetic seed prompts
  router/, hooks/, lib/      hash router, useLoad hook, formatting helpers
```

## Switching to the real backend

Every exported function in `src/services/api.js` corresponds to one backend call. Keep the names, arguments and returned shapes, and replace the bodies with `fetch` calls. Suggested mapping (adjust to your backend spec):

| Function | Suggested endpoint |
|---|---|
| `login(username, password)` | `POST /auth/login` |
| `logout()` | `POST /auth/logout` |
| `getSession()` | `GET /auth/session` |
| `sendPrompt(user, text)` | `POST /chat` |
| `getMyHistory(user)` | `GET /chats/mine` |
| `getTeamActivity(user)` | `GET /team/activity` |
| `flagPrompt(user, recordId)` | `POST /chats/{id}/flag` |
| `getAllChats(user)` | `GET /admin/chats` |
| `getAccounts(user)` | `GET /admin/accounts` |
| `setAccountStatus(user, id, active)` | `PATCH /admin/accounts/{id}` |
| `getAuditLog(user)` | `GET /admin/audit` |

Things to do at that point:

- `getSession()` is synchronous in the mock. With a real token or cookie it will be asynchronous, so initialise `AuthProvider` with a loading state.
- Remove `src/data/demoUsers.js`, `src/data/seedPrompts.js`, `src/services/gateway.js` and `src/services/storage.js`. Credentials, the vault and masking must live only on the backend.
- The backend decides what each role receives. A manager response must not contain original prompts or AI replies, and a worker response must contain only that worker's own records.

## Known limitations

- The mock detection is pattern-based (emails, card numbers, Aadhaar-like IDs, API keys, file paths, salary amounts, customer IDs, a few names). It will miss some values and flag some harmless text, as the project documentation warns.
- Demo data lives in `localStorage` in the browser. It is not secure and is not shared between browsers. Use **Accounts, Reset demo data** as an administrator to restore the starting state.
- The AI reply is a canned response built from the masked prompt, not a real model.
