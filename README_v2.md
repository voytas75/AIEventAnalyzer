# AI Event Analyzer

[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Start-AIEventAnalyzer)](https://www.powershellgallery.com/packages/Start-AIEventAnalyzer)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/853f8db7b74547bfbb46313d34838b62)](https://app.codacy.com/gh/voytas75/AIEventAnalyzer/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

`Start-AIEventAnalyzer.ps1` is a PowerShell script for analyzing **Windows Event Logs** with help from **Azure OpenAI** through the [`PSAOAI`](https://github.com/voytas75/PSAOAI) module.

It is intended for administrators, support engineers, and IT professionals who need a faster way to review recent Windows event data, generate troubleshooting ideas, and summarize noisy logs into actionable next steps. It is most useful when manual log review is too slow, repetitive, or hard to interpret at scale.

It lets you:
- choose an analysis action such as **Analyze**, **Troubleshoot**, **Correlate**, or **Summarize**,
- select a Windows event log and severity level,
- send recent event data to Azure OpenAI,
- review AI-generated follow-up prompts and responses,
- save results to log files for later reference.

## Requirements

- **Windows PowerShell / PowerShell** with access to **Windows Event Logs**
- **Windows operating system** (the main functionality depends on `Get-WinEvent` and Windows event log access)
- Internet connectivity to Azure OpenAI
- Azure OpenAI access configured for the `PSAOAI` module
- Installed PowerShell module: [`PSAOAI`](https://www.powershellgallery.com/packages/PSAOAI/)

> **Note**
> This project is intended for Windows environments. It is not expected to work functionally on Linux, macOS, or WSL because those environments do not provide native access to Windows Event Logs in the same way.

## Installation

Install the required module:

```powershell
Install-Module PSAOAI -Force
```

Install the script from PowerShell Gallery:

```powershell
Install-Script Start-AIEventAnalyzer -Force
```

Update the script later with:

```powershell
Update-Script Start-AIEventAnalyzer -Force
```

## Azure OpenAI environment variables

Before running the script, configure the environment variables required by `PSAOAI`:

- `API_AZURE_OPENAI_KEY` - Azure OpenAI API key
- `API_AZURE_OPENAI_ENDPOINT` - Azure OpenAI endpoint, for example:
  `https://<RESOURCE_NAME>.openai.azure.com`
- `API_AZURE_OPENAI_DEPLOYMENT` - deployment name used by the model
- `API_AZURE_OPENAI_APIVERSION` - Azure OpenAI API version

Example:

```powershell
$env:API_AZURE_OPENAI_KEY = "<your-key>"
$env:API_AZURE_OPENAI_ENDPOINT = "https://<resource>.openai.azure.com"
$env:API_AZURE_OPENAI_DEPLOYMENT = "gpt-4"
$env:API_AZURE_OPENAI_APIVERSION = "2024-02-01"
```

> **Data handling note**
> The function sends selected Windows event data to Azure OpenAI for analysis. Before using it in production, review whether the chosen event log entries may contain sensitive, personal, or security-relevant information.

## Quick start

Minimal happy-path:

```powershell
Install-Module PSAOAI -Force
Install-Script Start-AIEventAnalyzer -Force
Start-AIEventAnalyzer
```

If the script is installed but PowerShell cannot find it by name, it is often because `Install-Script` places scripts in a folder that is not automatically added to `PATH`.

### Option 1: Run the installed script

If the script is installed and available in your PowerShell path:

```powershell
Start-AIEventAnalyzer
```

If PowerShell cannot find the script by name, check where it was installed:

```powershell
Get-InstalledScript Start-AIEventAnalyzer | Select-Object InstalledLocation
```

Then either:
- run it using the full path, or
- add the install folder to your `$env:PATH`

Example:

```powershell
& "<InstalledLocationFolder>\Start-AIEventAnalyzer.ps1"
```

### Option 2: Run the local repository copy

From the project folder:

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer
```

## Usage modes

The script supports two usage modes.

### 1. Interactive mode

Run the function without parameters:

```powershell
Start-AIEventAnalyzer
```

In interactive mode, the function prompts you to choose:
- analysis action,
- event log name,
- severity level,
- number of recent events to analyze.

### 2. Parameter-driven mode

You can also call the function with parameters:

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer -LogName "Microsoft-Windows-AAD/Operational" -Serverity All -Action Optimize -Events 50
```

> **Important**
> The current function uses the parameter name **`-Serverity`**.
> This spelling is preserved here intentionally to match the actual implementation.

## Parameters

| Parameter | Required | Description |
|---|---:|---|
| `LogName` | No | Windows event log name to analyze. If omitted, the script prompts you to choose one. |
| `Serverity` | No | Severity level filter. Supported values: `Critical`, `Error`, `Warning`, `Information`, `Verbose`, `All`. |
| `Action` | No | Analysis action. Supported values: `Analyze`, `Troubleshoot`, `Correlate`, `Predict`, `Optimize`, `Audit`, `Automate`, `Educate`, `Documentation`, `Summarize`. |
| `Events` | No | Number of most recent events to analyze. |
| `LogFolder` | No | Output folder for saved log files. If omitted, the script uses `AIEventAnalyzer` under the user's Documents folder. |

## What the script does

At a high level, the workflow is:

1. Show a banner and check for newer script versions.
2. Load the `PSAOAI` module.
3. Let the user choose an analysis action or accept parameters.
4. Read Windows event log entries with the selected filters.
5. Generate AI prompts tailored to the selected action.
6. Run AI analysis on the selected event data.
7. Save session data and responses to log files.
8. Optionally summarize the session before exit.

## Analysis actions

The script supports these actions:

- `Analyze`
- `Troubleshoot`
- `Correlate`
- `Predict`
- `Optimize`
- `Audit`
- `Automate`
- `Educate`
- `Documentation`
- `Summarize`

These actions influence the system prompt sent to Azure OpenAI and determine the style of generated follow-up prompts.

## Output and log files

By default, output is stored in:

```text
%USERPROFILE%\Documents\AIEventAnalyzer
```

or, from PowerShell:

```powershell
[Environment]::GetFolderPath("MyDocuments")
```

The script writes plain-text log files. In practice, each run creates timestamped files whose names are based on the selected action, event log, severity level, and time of execution.

The generated files capture:
- selected action, event log, severity, and event count,
- prompt content,
- AI responses,
- session-related information.

> **Note**
> The exact filename shape comes from the current script implementation. Event log names may contain characters that are relevant to file naming, so this behavior should be treated as implementation-dependent.

If you want to use a custom output location:

```powershell
Start-AIEventAnalyzer -LogFolder "C:\Logs\AIEventAnalyzer"
```

## Examples

### Interactive analysis

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer
```

### Optimization-focused analysis of a specific event log

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer -LogName "Microsoft-Windows-AAD/Operational" -Serverity All -Action Optimize -Events 50
```

### Troubleshoot recent errors from the System event log

Use this when you want the AI to focus on recent `Error` events from the `System` log and propose likely causes or next diagnostic steps.

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer -LogName "System" -Serverity Error -Action Troubleshoot -Events 25
```

### Save output to a custom folder

```powershell
. .\Start-AIEventAnalyzer.ps1
Start-AIEventAnalyzer -LogName "System" -Serverity Error -Action Troubleshoot -Events 25 -LogFolder "C:\Temp\AIEventAnalyzer"
```

## Limitations

- The script is designed primarily for **interactive use**.
- It depends on the external `PSAOAI` module and Azure OpenAI availability.
- Output quality depends on the selected model, prompt quality, and the event data provided.
- Large logs or expensive queries may take time.
- Because the project focuses on Windows Event Logs, non-Windows environments are out of scope.

## Troubleshooting

### The script does not start by name

Check the install location:

```powershell
Get-InstalledScript Start-AIEventAnalyzer | Select-Object InstalledLocation
```

Then run the script by full path or add the install folder to `$env:PATH`.

### PSAOAI is missing

Install it with:

```powershell
Install-Module PSAOAI -Force
```

### Azure OpenAI variables are not configured

Verify the values:

```powershell
Get-ChildItem Env:API_AZURE_OPENAI*
```

### The script runs but analysis is empty or fails

Check:
- whether the selected event log contains matching events,
- whether Azure OpenAI credentials and deployment are valid,
- whether the `PSAOAI` module works independently.

## Notes for maintainers

A few details are worth keeping explicit in documentation:

- the function name is `Start-AIEventAnalyzer`,
- the current parameter name is `Serverity` (not `Severity`),
- the script is both installable from PowerShell Gallery and runnable from source,
- the main behavior is interactive, even though parameters are also supported.

## Project links

- GitHub: <https://github.com/voytas75/AIEventAnalyzer>
- PowerShell Gallery script: <https://www.powershellgallery.com/packages/Start-AIEventAnalyzer>
- PowerShell Gallery module: <https://www.powershellgallery.com/packages/PSAOAI/>
