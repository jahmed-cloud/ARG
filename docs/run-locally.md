# Run ARG Locally

How to start the ARG local portal on your workstation, sign in, view reports, and stop everything again.
It uses your own `az login` session. There's no Docker, database or service principal.

For all analysis options, the report layout and thresholds, see [subscription-analysis.md](./subscription-analysis.md).

The examples use `C:\src\ARG` as the repository root. Replace it with your checkout path.

---

## 1. Summary

| Item | Value |
|---|---|
| Start command | `C:\src\ARG\scripts\Start-LocalPortal.ps1` (from any folder) |
| URL | `http://127.0.0.1:8765/` (loopback only, so other machines can't reach it) |
| Username | `admin`, or the value of `ARG_PORTAL_USER` |
| Password | The value of `ARG_PORTAL_PASSWORD`. If it isn't set, a new one-time password is printed in the terminal on every start |
| Azure identity | Your `az login` session. The portal login never signs in to Azure |
| Reports folder | `C:\src\ARG\reports\<subscription>\` (git-ignored) |
| Stop | Ctrl+C in the portal terminal, or see [§8](#8-stop-everything) |

---

## 2. Prerequisites (one-time)

```powershell
python --version        # 3.10 or later
az --version            # Azure CLI
```

Your Azure account needs these roles on every subscription you want to analyse:

| Role | Used for |
|---|---|
| Reader | Resources, configuration, metrics |
| Cost Management Reader | Cost trend, per-resource cost, savings |
| Security Reader | Defender plans and recommendations |

A missing role doesn't stop a run. That part of the report is empty and the reason is listed under *Collection
Warnings* in `05-deep-dive/README.md`.

---

## 3. Sign in to Azure

```powershell
az login                                   # or: az login --tenant <tenant-id>
az account show --query "{user:user.name, tenant:tenantId}" -o table
```

Conditional Access can require a new sign-in about every hour (`AADSTS70043`). Run `az login` again and click
**Refresh** in the portal.

---

## 4. Set the portal login

Choose one of the options below.

**Option A: persistent (recommended).** Set it once for your Windows user:

```powershell
[Environment]::SetEnvironmentVariable('ARG_PORTAL_USER', '<username>', 'User')
[Environment]::SetEnvironmentVariable('ARG_PORTAL_PASSWORD', '<password>', 'User')
```

> **Important:** `'User'` scope only applies to terminals (and VS Code windows) opened **afterwards**. The terminal
> you ran it in keeps the old values, so a portal started there rejects the new password. Either open a new terminal,
> or also load the values into the current one:
>
> ```powershell
> $env:ARG_PORTAL_USER     = [Environment]::GetEnvironmentVariable('ARG_PORTAL_USER', 'User')
> $env:ARG_PORTAL_PASSWORD = [Environment]::GetEnvironmentVariable('ARG_PORTAL_PASSWORD', 'User')
> ```

**Option B: this terminal only.**

```powershell
$env:ARG_PORTAL_USER     = '<username>'
$env:ARG_PORTAL_PASSWORD = '<password>'
```

**Option C: nothing.** The username is `admin` and a one-time password is printed at start-up.

The portal reads these values **once, at start-up**. After changing them, restart the portal.

Check what the current terminal will use, without printing the password:

```powershell
"user: $env:ARG_PORTAL_USER   password set: $([bool]$env:ARG_PORTAL_PASSWORD)"
```

Never commit the password or put it in a script in the repository.

---

## 5. Start the portal

### Option A: launcher script (recommended)

```powershell
C:\src\ARG\scripts\Start-LocalPortal.ps1
```

- It works from any folder, because it switches to the repository root itself.
- The first run creates `.venv-local` and installs `requirements-local.txt`, which takes a minute or two.
- It opens the browser. Add `-NoBrowser` to skip that.
- Other options: `-Port 8766`, `-ReportsPath D:\arg-reports`, `-TenantId <id>`.
- **Keep the terminal open.** The portal only runs while that terminal runs.

Expected output:

```text
ARG local portal
  URL          : http://127.0.0.1:8765/
  Portal login : <username> / (ARG_PORTAL_PASSWORD)
  Reports dir  : C:\src\ARG\reports
  Azure CLI    : you@contoso.com (tenant <tenant-id>)
  Stop with Ctrl+C
```

If `Portal login` shows `admin / <random>   <- one-time password for this run`, no password was set in that
terminal. Use the printed one, or see [§4](#4-set-the-portal-login).

### Option B: manual (python)

```powershell
cd C:\src\ARG                                        # must be the repository root

# first time only: skip these two lines if .venv-local already exists
python -m venv .venv-local
.\.venv-local\Scripts\pip install -r requirements-local.txt

.\.venv-local\Scripts\Activate.ps1
python -m scripts.local_portal --port 8765             # options: --no-browser --reports-dir <dir> --tenant <id> --workers 2
```

Don't run `python -m venv .venv-local` while the venv is active or a portal is running. It fails with
`Permission denied: ...\.venv-local\Scripts\python.exe` because that file is in use. To rebuild the venv, see
[§9](#9-reset-the-virtual-environment).

### Option C: VS Code (run or debug)

1. Open the repository folder in VS Code **after** setting the variables in [§4](#4-set-the-portal-login).
2. Select `.venv-local\Scripts\python.exe` as the interpreter (**Python: Select Interpreter**).
3. Add `.vscode\launch.json`:

   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "ARG local portal",
         "type": "debugpy",
         "request": "launch",
         "module": "scripts.local_portal",
         "args": ["--port", "8765", "--no-browser"],
         "cwd": "${workspaceFolder}",
         "justMyCode": true
       }
     ]
   }
   ```

4. Press F5, then open `http://127.0.0.1:8765/`. Shift+F5 stops it.

---

## 6. View a report

1. Open `http://127.0.0.1:8765/` and sign in with the portal username and password.
2. The dashboard shows your `az login` account and every subscription it can see, with the latest report's
   Critical/High counts, 30-day cost and estimated savings.
3. **Existing report:** click the subscription name, or open **Reports** (`/reports`), which is the index of all
   analysed subscriptions. A report starts at `/reports/<subscription>/README.md`, and the sidebar links to:

   | Section | Content |
   |---|---|
   | `README.md` | Executive summary, savings, top risks, actions |
   | `01-current-findings` | Baseline, workloads, architecture diagram, inventory |
   | `02-gap-analysis` | Gaps by area and severity |
   | `03-cost-drivers` | 12-month trend, breakdown, forecast, savings register |
   | `04-architectural-critique` | Critique, target architecture, roadmap |
   | `05-deep-dive` | Per-area detail, collection warnings, raw JSON |

4. **New report:** tick one or more subscriptions, click **Analyze**, and watch the job table. A small subscription
   takes 3-4 minutes and a large one (about 2,000 resources) about 15. `429 … retrying` in the log is normal.
5. **PDF:** click **Export PDF (summary)** or **Export PDF (full)** on any report page. It's saved as
   `reports\<subscription>\report-<detail>.pdf`.

The reports are plain markdown files, so you can also open `C:\src\ARG\reports\<subscription>\README.md` in
VS Code.

Each git worktree has its own `reports\` folder. To view reports from another checkout, start with
`-ReportsPath C:\src\ARG\reports`.

---

## 7. Run an analysis without the portal (optional)

```powershell
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription '<name-or-id>' -Pdf summary
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'sub-a', 'sub-b'
C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -All
```

The output is the same `reports\<subscription>\` folder that the portal shows.

---

## 8. Stop everything

**Normal stop:** press **Ctrl+C** in the terminal running the portal, or close that terminal. In VS Code, press
Shift+F5. An analysis still running in the portal is cancelled and has to be run again.

**Portal running in another or hidden terminal:** find what is listening on the port and stop it:

```powershell
Get-NetTCPConnection -LocalPort 8765 -State Listen | Select-Object LocalPort, OwningProcess
Stop-Process -Id <OwningProcess>
```

**Stop every ARG portal and CLI analysis on the machine.** Each one shows up as two `python.exe` processes, the
`.venv-local` launcher and its child:

```powershell
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object CommandLine -match 'scripts\.(local_portal|subscription_analysis)' |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

**Check that the ports are free.** No output means nothing is listening:

```powershell
Get-NetTCPConnection -LocalPort 8765, 8766 -State Listen -ErrorAction SilentlyContinue
```

**Optional clean-up:**

```powershell
deactivate                                                     # leave the venv in this terminal
az logout                                                      # end the Azure CLI session
[Environment]::SetEnvironmentVariable('ARG_PORTAL_PASSWORD', $null, 'User')   # remove the saved portal password
```

---

## 9. Reset the virtual environment

Only needed if dependencies are broken.

```powershell
# 1. Stop every portal first (see §8), then:
cd C:\src\ARG
deactivate                                   # ignore the error if no venv is active
Remove-Item -Recurse -Force .venv-local
# 2. Let the launcher recreate it
.\scripts\Start-LocalPortal.ps1
```

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Login page rejects the password | The portal was started in a terminal that had an old or no `ARG_PORTAL_PASSWORD`. Values set with `SetEnvironmentVariable(..., 'User')` don't reach terminals that are already open | Stop the portal ([§8](#8-stop-everything)), open a new terminal (or load the values as in [§4](#4-set-the-portal-login)), and start it again. Check the `Portal login` line in the start-up output |
| Login rejected, and the start-up output shows `admin / <random>` | No password was set in that terminal | Use `admin` and the printed one-time password, or set the variables and restart |
| Login rejected, but the start-up output shows your username | Username and password are **case-sensitive**, or the browser autofilled an old saved password | Type both by hand (no leading or trailing spaces, Caps Lock off), or use a private window. Only one portal should be running on the port ([§8](#8-stop-everything)) |
| Dashboard shows "Failed to invoke the Azure CLI" right after sign-in | The first `az` call timed out while the portal was starting | Click **Refresh**. If it persists, run `az login` in a terminal and click **Refresh** again |
| `Permission denied: ...\.venv-local\Scripts\python.exe` | `python -m venv .venv-local` was run while the venv was active or a portal was running | Skip that command because the venv already exists. To rebuild it, see [§9](#9-reset-the-virtual-environment) |
| `ERR_CONNECTION_REFUSED` | The portal isn't running | Start it and keep the terminal open |
| Portal doesn't start, or an old portal answers on 8765 | Another portal already has the port | Stop it ([§8](#8-stop-everything)) or use `-Port 8766` |
| "The Azure CLI is not signed in", `AADSTS70043`, or "did not respond" | The `az login` session expired | Run `az login`, then click **Refresh** |
| A subscription is missing | It's in another tenant, or it's disabled | `az login --tenant <id>`, then click **Refresh** |
| Reports list is empty | The portal reads the `reports\` folder of the checkout it was started from | Start it from the right checkout, or pass `-ReportsPath` |
| Cost or Defender sections are empty | A role is missing | Grant *Cost Management Reader* / *Security Reader* |
| `No module named scripts` | `python -m …` was run outside the repository root | `cd C:\src\ARG`, or use the launcher script |
| `PDF not created` | No Edge or Chrome was found | Open `report-<detail>.html` and use **Print > Save as PDF** |
