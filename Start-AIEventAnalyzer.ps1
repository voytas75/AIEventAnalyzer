<#PSScriptInfo

.VERSION 1.1

.GUID 4ff39349-66db-44eb-a12f-eb4249b0f24b

.AUTHOR Voytas

.COMPANYNAME

.COPYRIGHT

.TAGS Events,AZURE,OpenAI

.LICENSEURI

.PROJECTURI https://github.com/voytas75/AIEventAnalyzer

.ICONURI

.EXTERNALMODULEDEPENDENCIES PSAOAI

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
unpublished - new repo site.
  1.1 - add check update (#15), Stream response as default (not-Stream in generating prompts only), fix filtering events by serveritylevel.
  1.0 - initializing

.PRIVATEDATA

#>

<#

.DESCRIPTION
 Analyze Windows event logs using AZURE OpenAI (PSAOAI Module).

 #>
using namespace System.Diagnostics
 
Param()

function Start-AIEventAnalyzer {
  [CmdletBinding(DefaultParameterSetName = "Default")]
  param (
    [Parameter(Mandatory = $true, ParameterSetName = "LogName")]
    [string]$LogName,
    [Parameter(Mandatory = $false, ParameterSetName = "LogName")]
    [ValidateSet("Critical", "Error", "Warning", "Information", "Verbose", "All")]
    [string]$Serverity,
    [Parameter(Mandatory = $false, ParameterSetName = "LogName")]
    [ValidateSet("Analyze", "Troubleshoot", "Correlate", "Predict", "Optimize", "Audit", "Automate", "Educate", "Documentation", "Summarize")]
    [string]$Action,
    [Parameter(Mandatory = $false, ParameterSetName = "LogName")]
    [int]$Events,
    [Parameter(Mandatory = $false)]
    [string]$LogFolder
  )

  if ([string]::IsNullOrEmpty($LogFolder)) {
    $script:LogFolder = Join-Path -Path ([Environment]::GetFolderPath("MyDocuments")) -ChildPath "AIEventAnalyzer"
    if (-not (Test-Path -Path $script:LogFolder)) {
      New-Item -ItemType Directory -Path $script:LogFolder | Out-Null
    }
  }
  Write-Host "[Info] The logs will be saved in the following folder: $script:LogFolder" -ForegroundColor DarkGray
  Write-Host ""
        
  # Define the prompts for the AI model
  $promptAnalyze = @'
Your task as a prompt maker is to develop a series of prompts designed to guide the incident analysis process, focusing on identifying root causes, understanding their impact, and proposing practical solutions or further investigative steps. It is critical in analyzing Windows events data to uncover patterns, anomalies, and insights that shed light on system performance, stability, and security. Responses must strictly follow the JSON format, ensuring clarity and consistency in the analysis process.
Example of a JSON response with two records:
``````json
[
  {
    "promptNumber": 1,
    "prompt": "Analyze the root cause of the W32time service stopping and assess if it is a regular behavior or an indication of an underlying issue.",
    "action": "Aznalyze",
    "analysisActions": [
      "Check if the service is configured to stop at scheduled times.",
      "Review system logs for any related errors or warnings.",
      "Verify if there was a system shutdown or restart."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Analyze the pattern of package installations and removals, and determine if there are any inconsistencies or issues with the update process.",
    "action": "Aznalyze",
    "analysisActions": [
      "Ensure that Adobe Acrobat is running the latest version.",
      "Review Adobe Acrobat's security settings and permissions.",
      "Check for any related security advisories from Adobe."
    ]
  }
]
``````
'@

  $promptTroubleshoot = @'
###Instruction###

Your job as a prompt creator is to develop a set of prompts based on the Windows event database to diagnose the root causes of problems that affect the performance, reliability or security of the system, propose targeted solutions and verify their effectiveness. These prompts MUST guide user through a systematic troubleshooting process, providing comprehensive analysis and resolution of identified issues. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Investigate the reason behind the change in the startup type of the Background Intelligent Transfer Service (BITS) and whether it aligns with system policies or user actions.",
    "action": "Troubleshoot",
    "analysisActions": [
      "Review recent administrative actions or group policies that might have changed the BITS configuration.",
      "Check if any software installations or updates require BITS to change its startup type.",
      "Ensure that the change does not affect any critical system updates or operations."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Analyze the implications of system session moves indicated by 'Kernel-Power' events and determine if they are expected transitions based on user interactions or system policies.",
    "action": "Troubleshoot",
    "analysisActions": [
      "Correlate the session moves with user login, unlock, or input events to confirm if they are user-initiated.",
      "Check for any power settings or scripts that might automate session state changes",
      "Ensure that these session changes do not indicate any instability or security concerns."
    ]
  }
]
'@

  $promptDocumentation = @'
###Instruction###

As a prompt creator, it's your responsibility to create prompts that help users gather relevant information from Windows events to include in your documentation. These prompts should focus on capturing key details such as event types, event IDs, timestamps, event messages, and any associated activities. Make sure your documentation provides a clear and concise overview of the events and their significance. Responses must strictly follow JSON to maintain consistency and facilitate easy referencing.

Example of a JSON response with two records:
[
    {
        "promptNumber": 1,
        "prompt": "A program has crashed. Identify the program name and any error code displayed (if applicable).",
        "action": "Documentation",
        "analysisActions": [
            "Identify if the crashing program is essential for system operation.",
            "Search for known issues or solutions related to the program name and error code (if available).",
            "Review application logs for additional details about the crash.",
            "Consider monitoring program performance to identify potential causes (e.g., resource exhaustion).",
            "If the program is critical, investigate potential workarounds or mitigation strategies."
        ]
    },
    {
        "promptNumber": 2,
        "prompt": "Are there any additional details or logs associated with the event?",
        "action": "Documentation",
        "analysisActions": [
            "Additional logs may provide more context about the event."
        ]
    }
]
'@

  $promptCorrelate = @'
###Instruction###

As a prompt creator, you're tasked with generating a series of prompts focused on identifying correlations between Windows events, determining their importance, and gaining actionable insights to gain deeper insights into system behavior and performance, and improve system management and troubleshooting processes. Responses must strictly follow the JSON format, which facilitates structured analysis and interpretation of correlated data.

Example of a JSON response with two records:
[
    {
        "promptNumber": 1,
        "prompt": "Identify events occurring immediately before or after a specific event type (e.g., system errors). Analyze the timestamps and event messages to determine potential cause-and-effect relationships.",
        "action": "Correlate",
        "analysisActions": [
            "Consider the logical sequence of events to identify potential dependencies.",
            "Focus on frequently occurring patterns of pre- and post-crash events to pinpoint potential root causes.",
            "Prioritize investigation based on the severity of the correlated event (e.g., high-impact errors)."
        ]
    },
    {
        "promptNumber": 2,
        "prompt": "Analyze trends in specific event types (e.g., security warnings) over time. Look for spikes or recurring patterns that might indicate ongoing issues or potential security threats.",
        "action": "Correlate",
        "analysisActions": [
            "Correlate event trends with system activities or configuration changes.",
            "Evaluate the potential impact of identified trends on system stability and security.",
            "Prioritize troubleshooting efforts based on the severity and frequency of the trending event type."
        ]
    }
]
'@

  $promptPredict = @'
###Instruction###

Your goal as a prompt maker is to create prompts to select appropriate predictive analytics techniques, train predictive models, and interpret predictive insights to predict the behavior of the system. These prompts should allow users to use predictive analytics to optimize system performance and mitigate potential risks. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Identify historical event patterns that might be indicative of future occurrences (e.g., cyclical resource usage spikes). Select appropriate predictive modeling techniques (e.g., time series forecasting) based on the identified patterns and desired outcome.",
    "action": "Predict",
    "analysisActions": [
      "Consider the volume and frequency of historical events for choosing suitable modeling techniques.",
      "Evaluate the desired prediction timeframe (short-term vs. long-term) when selecting a model.",
      "Prioritize techniques that align with system performance metrics you aim to predict (e.g., resource utilization, application response times)."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Train and validate a predictive model using historical event data. Analyze the model's performance metrics (e.g., accuracy, precision) to assess its reliability for forecasting future events. Interpret the model's predictions in the context of system behavior and resource allocation.",
    "action": "Predict",
    "analysisActions": [
      "Fine-tune model parameters for optimal predictive performance.",
      "Monitor the model's predictions over time and retrain it if significant deviations occur.",
      "Use the model's insights to proactively allocate resources and mitigate potential performance bottlenecks.",
      "Evaluate the cost-benefit of implementing the predictive model based on its accuracy and impact on system management."
    ]
  }
]
'@

  $promptOptimize = @'
###Instruction###

As a prompt engineer, your job is to generate prompts based on insights from analyzing Windows event data to identify optimization opportunities, implement optimization strategies, and measure the impact of optimization efforts on system performance. These prompts should guide users through a systematic optimization process, ensuring continuous improvement and performance gains. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Analyze event data to identify bottlenecks or recurring issues that are impacting system performance or resource utilization (e.g., frequent disk I/O delays, high memory usage by specific applications).",
    "action": "Optimize",
    "analysisActions": [
      "Prioritize optimization efforts based on the severity and impact of identified bottlenecks.",
      "Consider potential solutions based on the nature of the issue (e.g., hardware upgrades, software configuration changes).",
      "Evaluate the cost-effectiveness of potential solutions before implementing them."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Implement and monitor the effectiveness of chosen optimization strategies. Analyze system performance metrics (e.g., CPU utilization, application response times) before and after optimization to measure the impact.",
    "action": "Optimize",
    "analysisActions": [
      "Correlate changes in event data with performance improvements after optimization.",
      "Continuously monitor system performance to identify new optimization opportunities.",
      "Refine or adjust optimization strategies based on ongoing analysis and performance metrics."
    ]
  }
]
'@

  $promptAudit = @'
###Instruction###

Your tasks as a prompt engineer are to develop prompts to define audit criteria, suggest how audit reviews are conducted, and document audit findings. These prompts should facilitate end-to-end auditing processes, ensuring that the user can effectively assess system compliance, audit Windows event logs to ensure compliance with general best practices for regulatory requirements, organizational policies, and system security. and identify areas for improvement. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Define specific audit criteria based on relevant regulations, organizational policies, and security best practices. Identify specific event types, user activities, or access attempts that require scrutiny during the audit.",
    "action": "Audit",
    "analysisActions": [
      "Consider the sensitivity of data and systems to determine appropriate audit criteria.",
      "Prioritize audit criteria based on the potential security risks and regulatory compliance requirements.",
      "Reference industry standards or security frameworks to ensure comprehensive audit coverage."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Conduct a thorough review of Windows event logs based on the defined criteria. Analyze identified events for potential security violations, policy breaches, or unauthorized access attempts. Document all audit findings, including timestamps, event details, and any remediation actions taken.",
    "action": "Audit",
    "analysisActions": [
      "Correlate events with user activity logs for additional context.",
      "Evaluate the potential impact of identified security events on system integrity and data confidentiality.",
      "Recommend appropriate corrective actions based on the audit findings (e.g., user account suspension, policy adjustments).",
      "Maintain clear and concise audit reports for future reference and regulatory compliance purposes."
    ]
  }
]
'@

  $promptAutomate = @'
###Instruction###

As a prompt engineer, your goal is to create prompts based on analysis of Windows event data, aimed at identifying automation opportunities, designing automated workflows, and implementing automation solutions. These prompts should enable the user to automate routine tasks, reduce manual effort, and improve overall operational efficiency. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Identify repetitive tasks or manual interventions triggered by specific Windows events (e.g., restarting a service after a crash, applying security updates). Analyze the frequency and impact of these tasks to determine their suitability for automation.",
    "action": "Automate",
    "analysisActions": [
      "Prioritize automation efforts based on the time saved and potential for human error reduction.",
      "Consider the complexity of the task and the availability of suitable automation tools.",
      "Evaluate the potential impact of automation failures and develop mitigation strategies."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Design an automated workflow that replicates the identified manual task using scripting languages or automation tools. Integrate event triggers and appropriate actions based on the analyzed event data. Test and refine the automation solution to ensure its reliability and effectiveness.",
    "action": "Automate",
    "analysisActions": [
      "Document the automation workflow clearly for future reference and maintenance.",
      "Schedule regular testing and monitoring of automated tasks to ensure ongoing functionality.",
      "Establish procedures for handling errors or unexpected events within the automated workflow.",
      "Continuously evaluate the effectiveness of automation and identify opportunities for further optimization."
    ]
  }
]
'@

  $promptEducate = @'
###Instruction###

As a prompt engineer, it's your job to develop prompts to create learning materials, conduct training sessions, or facilitate knowledge-sharing activities based on the results of Windows Event Analysis. These prompts should ensure that users can effectively communicate key concepts, best practices, and actionable insights to increase the understanding and proficiency of IT staff. Responses must strictly follow the JSON format.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Identify key themes or recurring issues revealed by your event data analysis. Consider common challenges faced by IT staff and areas where knowledge gaps might exist.",
    "action": "Educate",
    "analysisActions": [
      "Prioritize educational topics based on their potential impact on IT staff efficiency and system security.",
      "Tailor content to the specific needs and technical expertise of your audience.",
      "Incorporate real-world examples from your event analysis to illustrate key points and best practices."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Choose an appropriate educational format (e.g., training manuals, interactive workshops, knowledge-sharing sessions) that aligns with the identified content and target audience. Develop clear and concise learning objectives for your chosen format.",
    "action": "Educate",
    "analysisActions": [
      "Incorporate interactive elements or hands-on activities to enhance engagement and knowledge retention.",
      "Encourage discussions and knowledge sharing to foster collaboration among IT staff.",
      "Provide opportunities for feedback and evaluation to ensure the effectiveness of your educational materials."
    ]
  }
]
'@

  $promptSummarize = @'
###Instruction###

As a prompt engineer, it's your job to develop prompts that help users summarize the most critical aspects of Windows events, including notable patterns, significant anomalies, identified root causes, and recommended actions. You need to extract key insights and insights from your Windows event data in concise summaries for easy referencing and analysis.  These prompts should enable users to effectively communicate the essence of the data analysis process and its implications in a clear and concise manner. Responses must strictly follow JSON to maintain consistency and facilitate easy referencing.

Example of a JSON response with two records:
[
  {
    "promptNumber": 1,
    "prompt": "Did you encounter any high-severity events (e.g., errors, warnings)? If so, briefly describe them and note the timestamps for potential reference.",
    "action": "Summarize",
    "analysisActions": [
        "Classify the high-severity events by event type (e.g., security errors, application crashes).",
        "Evaluate the potential impact of each high-severity event on system stability, security, or functionality.",
        "Correlate high-severity events with other relevant events to identify potential root causes or contributing factors.",
        "Prioritize investigation and remediation efforts based on the severity and potential impact of the events.",
        "Consider referring to knowledge bases or vendor documentation for troubleshooting guidance specific to the identified high-severity events."
    ]
  },
  {
    "promptNumber": 2,
    "prompt": "Considering your findings, what specific actions are recommended to address identified problems or improve system health?",
    "action": "Summarize",
    "analysisActions": [
        "Prioritize recommendations based on their potential impact on mitigating risks or enhancing system performance.",
        "Align recommendations with the identified root causes of problems to ensure they address the underlying issues.",
        "Consider the feasibility and potential resource requirements for implementing each recommendation.",
        "Formulate clear and actionable steps for each recommendation, including specific configuration changes, security updates, or troubleshooting procedures.",
        "Estimate the expected timeframe for implementing the recommendations and their potential impact on system downtime (if applicable).",
        "Develop a plan for monitoring the effectiveness of implemented recommendations and identify the need for further adjustments."
    ]
  }
]
'@

  # Define the list of actions
  $actions = @("Analyze", "Troubleshoot", "Correlate", "Predict", "Optimize", "Audit", "Automate", "Educate", "Documentation", "Summarize")
  # Define the list of prompts corresponding to each action
  $prompts = @($promptAnalyze, $promptTroubleshoot, $promptCorrelate, $promptPredict, $promptOptimize, $promptAudit, $promptAutomate, $promptEducate, $promptDocumentation, $promptSummarize)
  
  if (-not $Action) {
    do {
      # Display the list of actions to the user
      Write-Host "Please choose an action for Windows events:" -ForegroundColor DarkCyan
      for ($i = 0; $i -lt $actions.Length; $i++) {
        Write-Host "$($i+1). $($actions[$i])" -ForegroundColor Cyan
      }
      Write-Host ""
  
      # Ask the user to choose an action
      Write-Host "Enter the number of your chosen action (default: 1 - Analyze)" -ForegroundColor DarkCyan -NoNewline
      $chosenActionIndex = Read-Host " "
      if ([string]::IsNullOrEmpty($chosenActionIndex)) {
        $chosenActionIndex = 1
        break
      }
      # Validate the user's input
    } while ($chosenActionIndex -notmatch '^\d+$' -or [int]$chosenActionIndex -lt 1 -or [int]$chosenActionIndex -gt $actions.Length)
    Write-Verbose $chosenActionIndex

    # Get the chosen action and corresponding prompt
    $chosenAction = $actions[$chosenActionIndex - 1]
    Write-Verbose $chosenAction 
    $prompt_one = $prompts[$chosenActionIndex - 1]
    Write-Verbose $prompt_one
  }
  else {
    $ActionIndex = $actions.IndexOf($Action)
    $prompt_one = $prompts[$ActionIndex]
    $chosenAction = $Action
  }
    
  # Display the chosen action to the user
  Write-Host "Your selected action is: $chosenAction" -ForegroundColor Green
  Write-Host ""  
  # Clean the system prompt by removing non-ASCII characters
  $prompt_one = [System.Text.RegularExpressions.Regex]::Replace($prompt_one, "[^\x00-\x7F]", " ")        

  # Get a list of all Windows event logs, sort them by record count in descending order, and select the top 25 logs
  $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Sort-Object RecordCount -Descending | Select-Object LogName, RecordCount
  if (-not $LogName) {
    $minEventCountDefault = 2100
    Write-Host "Please enter the minimum number of events a log should have to be shown in the list." -ForegroundColor DarkCyan
    Write-Host "Enter the minimum event count (default: $minEventCountDefault)" -ForegroundColor DarkCyan -NoNewline
    $minEventCount = Read-Host " "
    if ([string]::IsNullOrEmpty($minEventCount) -or $minEventCount -lt 0) {
      $minEventCount = $minEventCountDefault
    }
    Write-Host "You have chosen to display logs with at least $minEventCount events." -ForegroundColor Green
    Write-Host ""
  
    $logs = $logs | Where-Object { $_.RecordCount -ge $minEventCount }

    # Display the name and record count of each log
    #$logs | ForEach-Object {Write-Host "$($_.LogName) - $($_.RecordCount) records"}
    try {
      $LogsFiltered = $logs.where{ $_.RecordCount -gt $minEventCount }
      foreach ($log in $LogsFiltered) {
        Write-Host "$($log.LogName) - " -ForegroundColor Cyan -NoNewline
        Write-Host "$($log.RecordCount) records" -ForegroundColor DarkCyan
      }
    }
    catch [System.Management.Automation.HaltCommandException] {
      # Handle termination here (e.g., write message)
      Write-Host "Command stopped by user (Quit)" -ForegroundColor DarkMagenta
    
    }
    Write-Host ""

    $LogNameDefault = $logs[0].LogName
    # Prompt the user to enter the log name for analysis
    Write-Host "Please enter the LogName from the list above to analyze events (default: $LogNameDefault)" -ForegroundColor DarkCyan -NoNewline
    $chosenLogName = Read-Host " "
  
    # Check if the chosen log name is empty or null. If it is, set it to the first log name in the logs list
    if ([string]::IsNullOrEmpty($chosenLogName)) {
      $chosenLogName = $LogNameDefault
    }
  }
  else {
    $chosenLogName = $Logname  
  }
  
  Write-Host "You have chosen the log: $chosenLogName" -ForegroundColor Green
  Write-Host ""

  # Get the record count for the chosen log name
  $logRecordCount = ($logs | Where-Object { $_.logname -eq "$chosenLogName" }).Recordcount
  # Display the record count for the chosen log name
  Write-Host "The log '$chosenLogName' has $logRecordCount events of all severity levels."
  Write-Host ""
  
  # Loop until a valid severity level is entered
  do {
    if (-not $Serverity) {
      Write-Host "Counting the number of events for each severity level, this may take some time..." -ForegroundColor DarkCyan
      $severityLevels = @("Critical", "Error", "Warning", "Information", "Verbose")
      foreach ($level in $severityLevels) {
        $count = Get-EventLogInfo -logName $chosenLogName -severityLevel $level
        Write-Host "The log '$chosenLogName' has $count events of '$level' severity level." -ForegroundColor DarkCyan
      }
      Write-Host ""
    
      # Ask the user to enter the severity level
      Write-Host "Please enter the severity level of the events you want to analyze. Options are: Critical, Error, Warning, Information, Verbose, or All." -ForegroundColor DarkCyan
      Write-Host "Enter the severity level (default: All)" -ForegroundColor DarkCyan -NoNewline
      $chosenSeverityLevel = Read-Host " "
    }
    else {      
      $chosenSeverityLevel = $Serverity
      if ($Serverity -ne "All") {
        Write-Host "You have chosen the severity level: $chosenSeverityLevel ($(Get-EventSeverity -Severity $chosenSeverityLevel))" -ForegroundColor Green
        Write-Host "Counting the number of events, this may take some time..." -ForegroundColor DarkCyan
      }
    }
    # If the entered severity level is valid, get the events for that severity level
    if ($chosenSeverityLevel -in @("Critical", "Error", "Warning", "Information", "Verbose")) {
      if (-not $Serverity) {
        Write-Host "You have chosen the severity level: $chosenSeverityLevel ($(Get-EventSeverity -Severity $chosenSeverityLevel))" -ForegroundColor Green
      }      
      $filterXPath = "*[System[(Level=$(Get-EventSeverity -Severity $chosenSeverityLevel))]]"
      $data_to_analyze = Get-WinEvent -LogName $chosenLogName -FilterXPath $filterXPath -ErrorAction SilentlyContinue | Select-Object Message, Level, ProviderName, ProviderId, LogName, TimeCreated 
      $logRecordServerityCount = $data_to_analyze.Count
      Write-Host ""
    }
    # If the entered severity level is empty or null, set it to "All" and get all events
    elseif ([string]::IsNullOrEmpty($chosenSeverityLevel)) {
      $chosenSeverityLevel = "All"
      $logRecordServerityCount = $logRecordCount
      Write-Host "You have chosen the severity level: $chosenSeverityLevel" -ForegroundColor Green
      Write-Host ""
    }
    # If the entered severity level is invalid, set it to "All" and get all events
    else {
      $chosenSeverityLevel = "All"
      $logRecordServerityCount = $logRecordCount
      Write-Host "You have chosen the severity level: $chosenSeverityLevel" -ForegroundColor Green
      Write-Host ""
    }
  } until ([int]$logRecordServerityCount -gt 0)
  
  
  if (-not $Events) {
    $logRecordServerityCountDefault = 50
    if ($logRecordServerityCount -lt $logRecordServerityCountDefault) {
      $logRecordServerityCountDefault = $logRecordServerityCount
    }
    # Ask the user to enter the number of most recent events they want to analyze
    Write-Host "Please enter the number of most recent '$chosenLogName' for '$chosenSeverityLevel' serverity events you want to analyze (1-$logRecordServerityCount) (default: $logRecordServerityCountDefault)" -ForegroundColor DarkCyan -NoNewline
    $chosenLogNameNewest = Read-Host " "

    # If the entered number is empty or null, set it to 10
    if ([string]::IsNullOrEmpty($chosenLogNameNewest)) {
      $chosenLogNameNewest = $logRecordServerityCountDefault
    }
  }
  else {
    $chosenLogNameNewest = $Events
  }
  Write-Host "You have chosen $chosenLogNameNewest most recent events." -ForegroundColor Green
  Write-Host ""

  # If the chosen severity level is not valid, get the most recent events up to the entered number
  if ($chosenSeverityLevel -notin @("Critical", "Error", "Warning", "Information", "Verbose")) {
    $data_to_analyze = Get-WinEvent -LogName $chosenLogName -MaxEvents $chosenLogNameNewest | Select-Object Message, Level, ProviderName, ProviderId, LogName, TimeCreated 
  }
  else {
    $data_to_analyze = $data_to_analyze | Select-Object -First $chosenLogNameNewest | Select-Object Message, Level, ProviderName, ProviderId, LogName, TimeCreated 
  }
  $logRecordServerityCount = $data_to_analyze.Count
  $data_to_analyze = $($data_to_analyze.foreach{ $(Format-ContinuousText $_.Message) + ', ' + $_.ProviderName }) + "`n Analyze data and response as JSON" | Out-String
  
  # Display the chosen log name, severity level, and event count
  Write-Host "Action: $chosenAction" -ForegroundColor Yellow
  Write-Host "LogName: $chosenLogName" -ForegroundColor Magenta
  Write-Host "Level: $chosenSeverityLevel" -ForegroundColor Blue
  Write-Host "Event count: $logRecordServerityCount (all: $logRecordCount)"  -ForegroundColor Yellow 
  Write-Host ""

  $currentDateTime = Get-Date -Format "yyyyMMdd-HHmmss"
  $chosenLogName = $chosenLogName -replace '[\\/:*?"<>|]', '_'
  $logFileName = "$chosenAction-$chosenLogName-$chosenSeverityLevel-$currentDateTime.txt"
  $data_to_file = [ordered]@{
    "Action"     = $chosenAction
    "LogName"    = $chosenLogName
    "Level"      = $chosenSeverityLevel
    "EventCount" = $logRecordServerityCount
    "All Events" = $logRecordCount
    "Prompt"     = (Format-ContinuousText -text $prompt_one)
  }
  foreach ($key in $data_to_file.Keys) {
    LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "$key : $($data_to_file[$key])" -Type "user"
  }

  $logFileNameEventData = "$chosenAction-$chosenLogName-$chosenSeverityLevel-EventData-$currentDateTime.txt"
  $logFileNameEventData = Join-Path $script:LogFolder $logFileNameEventData
  LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Log file with events data: $logFileNameEventData" -Type "other"

  Write-Verbose "Log with event data: $logFileNameEventData"

  # Invoke the AI model with the prompt and the data to analyze
  do {
    $data_to_analyze = [System.Text.RegularExpressions.Regex]::Replace($data_to_analyze, "[^\x00-\x7F]", " ")        
    Write-Host "Generating prompts for '$chosenAction' action..." -ForegroundColor Green -NoNewline
    $json_data = $data_to_analyze | ConvertTo-Json | out-string | Invoke-AIEventAnalyzer -NaturalLanguageQuery $prompt_one -LogFile $logFileNameEventData -Verbose:$true -Stream $false
    if (-not [string]::IsNullOrEmpty($json_data)) {
      break
    }
    Write-Host "Do you want to run the analysis again? (Y/N)" -ForegroundColor Cyan
    $userInput = Read-Host
  } while ($userInput -eq 'Y' -or $userInput -eq 'y')

  write-Verbose ($json_data | out-string)
  
  if ([string]::IsNullOrEmpty($json_data)) {
    LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Empty response for '$chosenAction' action." -Type "system"
    Write-Host "No response received. Possible reasons: Distraction by other tasks, Technical issues (e.g., network problems), System overload or slow performance, Miscommunication about the prompt's urgency, Accidental dismissal of the prompt, Interruptions (e.g., meetings, phone calls), Inattention or unawareness of the prompt, Time constraints due to busy schedule, Preference for delayed response, External factors (e.g., power outage)." -ForegroundColor Red

    Write-Host "`nNo data to analyze. Exiting script...`n" -ForegroundColor Red
    return
  }

  LogData -LogFolder $script:LogFolder -FileName $logFileName -Data ($json_data | Out-String) -Type "system"
  
  # Clean the returned JSON data
  $json_data = Clear-LLMDataJSON -data $json_data

  LogData -LogFolder $script:LogFolder -FileName $logFileName -Data ($json_data | ConvertTo-Json -Depth 100) -Type "system"

  # Convert the cleaned JSON data to a PowerShell object
  $object_prompt = ($json_data | ConvertFrom-Json ) 

  Write-Host ""
  # Loop until the user chooses to quit
  while ($true) {
    # Display the prompt number and prompt
    $SubPrompts = $object_prompt
    #LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "All Sub-Prompts: $(Format-ContinuousText -text $($SubPrompts | Out-String))" -Type "system"
    #$SubPrompts | Format-List promptNumber, prompt | Out-Host -Paging
    foreach ($SubPrompt in $SubPrompts) {
      Write-Host "$($SubPrompt.promptNumber)} " -foregroundColor DarkGreen -NoNewline
      Write-Host "$($subPrompt.prompt)" -ForegroundColor Green
      Write-Host ""
    }
    Write-Host ""

    # Inform the user that they can quit the script at any time
    Write-Host "Enter 'Q' and ENTER to quit the script ( AI will do summarize of session )." -ForegroundColor DarkBlue
    Write-Host ""

    # Get the total number of prompts
    $prompt_count = $object_prompt.Count

    $choose_prompt_number = $null
    # Keep asking the user to choose a valid prompt number until they choose a number within the valid range
    do {
      if (-not [string]::IsNullOrEmpty($choose_prompt_number) -and [int]$choose_prompt_number -ge 1 -and [int]$choose_prompt_number -le $prompt_count) {
        Write-Host "Last chosen prompt number: $choose_prompt_number" -ForegroundColor DarkGreen
      }
      Write-Host "Choose the number of prompt to analyze events (1-$prompt_count)" -ForegroundColor Cyan -NoNewline
      $choose_prompt_number = Read-Host " "
      Write-Host ""

      # If the user chooses to quit, end the script
      if ($choose_prompt_number -eq 'q' -or $choose_prompt_number -eq 'Q') {
        # Display a message indicating that the script is quitting
        Write-Host "Quiting..."
        Write-Host ""

        # Log the quit action
        LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Quiting" -Type "user"

        # Get the details of the log file
        Get-LogFileDetails -LogFolder $script:LogFolder -logFileName $logFileName -LogEventDataFileName $logFileNameEventData
        Write-Host ""

        Get-SummarizeSession -LogFolder $script:LogFolder -logFileName $logFileName -Stream $true
        Write-Host ""
        # Break the loop to end the script
        # break
        return
      }
    } while ($choose_prompt_number -notmatch '^\d+$' -or [int]$choose_prompt_number -lt 1 -or [int]$choose_prompt_number -gt $prompt_count)
    
    # Construct the chosen prompt
    $choose_prompt = $($object_prompt[($choose_prompt_number - 1)].prompt)

    # Display the chosen prompt to the console
    Write-Host "Prompt: '$choose_prompt'" -ForegroundColor Green
    Write-Host ""
    # Log the chosen prompt
    LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Chosen Sub-Prompt: $(Format-ContinuousText -text $choose_prompt)" -Type "user"

    # Update the chosen prompt using the Update-PromptData function
    $choose_prompt = Update-PromptData -inputPrompt $choose_prompt
    # Display the updated prompt to the console
    Write-Host "Enriched Prompt: '$choose_prompt'" -ForegroundColor DarkGreen
    Write-Host ""
    # Log the updated prompt
    LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Chosen Sub-Prompt (updated): $(Format-ContinuousText -text $choose_prompt)" -Type "user"
    
    Write-Host "Generating response for the chosen prompt..." -ForegroundColor Cyan
    # Invoke the AI model with the chosen prompt and the data to analyze
    $dataSubpromptResponse = ($data_to_analyze | Invoke-AIEventAnalyzer -NaturalLanguageQuery $choose_prompt -LogFile $logFileNameEventData -Verbose:$false)
    LogData -LogFolder $script:LogFolder -FileName $logFileName -Data "Sub-Prompt response: $(Format-ContinuousText -text $dataSubpromptResponse)" -Type "system"
    Write-Host ""
    
    # Output the response data with paging
    $dataSubpromptResponse | Out-Host -Paging

    # Ask the user to press any key to continue
    Write-Host "Press any key to continue ..." -ForegroundColor Cyan
    $null = [Console]::ReadKey($true)
    Write-Host ""
  }
}


function LogData {
  <#
.SYNOPSIS
This function logs the data into a specified file in a specified folder.

.DESCRIPTION
The LogData function takes a log folder, filename, data, and type as parameters. 
It logs these parameters to a file in the specified folder. Each logged line includes the date, time, and type.

.PARAMETER LogFolder
This parameter accepts the folder where the log file will be stored.

.PARAMETER FileName
This parameter accepts the name of the file where the data will be logged.

.PARAMETER Data
This parameter accepts the data that needs to be logged.

.PARAMETER Type
This parameter accepts the type of the data that needs to be logged. The type can be "user", "system", or "other".

.EXAMPLE
LogData -LogFolder "C:\Logs" -FileName "log.txt" -Data "Some data to log" -Type "user"
#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$LogFolder,

    [Parameter(Mandatory = $true)]
    [string]$FileName,

    [Parameter(Mandatory = $true)]
    [string]$Data,

    [Parameter(Mandatory = $true)]
    [ValidateSet("user", "system", "other")]
    [string]$Type
  )

  # Create the log folder if it doesn't exist
  if (!(Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Force -Path $LogFolder
  }

  # Log the data, date, time, and type to the specified file in the specified folder
  $logFilePath = Join-Path -Path $LogFolder -ChildPath $FileName
  $logEntry = "{0}; {1}; {2}; {3}; {4}; {5}" -f (Get-Date), $Type, $Data, $null, $null, $null
  Add-Content -Path $logFilePath -Value $logEntry
}

function Invoke-AIEventAnalyzer {
  <#
.SYNOPSIS
This function uses Azure OpenAI to interpret the input using a language model and the user's query.

.DESCRIPTION
The Invoke-AICopilot function takes an input object and a natural language query as parameters. 
It converts the input object to a string and calls the Invoke-AzureOpenAIChatCompletion function to interpret the input using a language model and the user's query.

.PARAMETER InputObject
This parameter accepts the input object that needs to be interpreted.

.PARAMETER NaturalLanguageQuery
This parameter accepts the natural language query to interpret the input object.

.EXAMPLE
Invoke-AICopilot -InputObject $InputObject -NaturalLanguageQuery "Show only processes using more than 500MB of memory"
#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [object]$InputObject,

    [Parameter(Mandatory = $true, Position = 0)]
    [string]$NaturalLanguageQuery,

    [Parameter(Mandatory = $false)]
    [string]$LogFile,

    [bool]$stream = $true
  )

  begin {

    # This block runs once before any input is processed
    # Initialize an array to store the input objects
    $inputObjects = @()
  }

  process {
    # This block runs once for each item of input
    # Add the current input object to the array
    $inputObjects += $InputObject
  }

  end {
    # This block runs once after all input has been processed
    # Convert the array of input objects into a single string
    $inputString = $inputObjects | Out-String
    
    # Call the Invoke-AzureOpenAIChatCompletion function to interpret the input using a language model and the user's query
    $response = Invoke-PSAOAIChatCompletion -SystemPrompt $NaturalLanguageQuery -usermessage $inputString -OneTimeUserPrompt -Mode Precise -simpleresponse -LogFile $LogFile -Stream $Stream

    # Return the response from the Azure OpenAI Chat Completion function
    return $response 
  }
}

# This function is used to clear the LLMDataJSON
function Clear-LLMDataJSON {
  <#
.SYNOPSIS
This function clears the LLMDataJSON.

.DESCRIPTION
The Clear-LLMDataJSON function takes a string of data as input, finds the first instance of '[' and the last instance of ']', and returns the substring between these two characters. This effectively removes any characters before the first '[' and after the last ']'.

.PARAMETER data
A string of data that needs to be cleared.

.EXAMPLE
$data = "{extra characters}[actual data]{extra characters}"
Clear-LLMDataJSON -data $data
#>
  param (
    # The data parameter is mandatory and should be a string
    [Parameter(Mandatory = $true)]
    [string]$data
  )
  # Find the first occurrence of '[' and remove everything before it
  $data = $data.Substring($data.IndexOf('['))
  # Find the last occurrence of ']' and remove everything after it
  $data = $data.Substring(0, $data.LastIndexOf(']') + 1)
  # Return the cleaned data
  return $data
}

function Get-EventSeverity {
  # Define the parameters for the function
  param (
    # The Severity parameter is mandatory and should be an integer or a string
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (($_ -is [int] -and 1..5 -contains $_) -or ($_ -is [string] -and $_ -in "Critical", "Error", "Warning", "Information", "Verbose")) {
          $true
        }
        else {
          throw "Invalid input. Please enter an integer between 1 and 5 or a valid severity name."
        }
      })]
    $Severity
  )

  # Define the hash table for severity levels and their corresponding names
  $EventLevels = @{
    1 = "Critical"
    2 = "Error"
    3 = "Warning"
    4 = "Information"
    5 = "Verbose"
  }

  # Define the reverse hash table for severity names and their corresponding levels
  $EventLevelsReverse = $EventLevels.GetEnumerator() | Group-Object -Property Value -AsHashTable -AsString

  # Check if the input is an integer or a string and return the corresponding value
  if ($Severity -is [int]) {
    return $EventLevels[$Severity]
  }
  else {
    return ($EventLevelsReverse[$Severity]).Name
  }
}

function Get-EventLogInfo {
  <#
.SYNOPSIS
   This function retrieves the count of events from a specified Windows Event Log based on the severity level.

.DESCRIPTION
   The Get-EventLogInfo function creates an object of the specified Windows Event Log and filters the entries based on the provided severity level. 
   It then returns the count of the filtered events.

.PARAMETER logName
   The name of the Windows Event Log from which the events are to be retrieved.

.PARAMETER severityLevel
   The severity level of the events to be retrieved. The valid values are "Critical", "Error", "Warning", "Information", "Verbose", "SuccessAudit", "FailureAudit".

.EXAMPLE
   Get-EventLogInfo -logName "System" -severityLevel "Information"
   This command retrieves the count of "Information" level events from the "System" Windows Event Log.
#>
  param (
    [Parameter(Mandatory = $true)]
    [string]$logName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Critical", "Error", "Warning", "Information", "Verbose", "SuccessAudit", "FailureAudit")]
    [string]$severityLevel
  )

  # Create an object of the specified Windows Event Log
  $eventLog = new-object System.Diagnostics.EventLog($logName)

  try {
    # Filter the entries of the Event Log based on the provided severity level
    $filteredEvents = $eventLog.Entries | Where-Object { $_.EntryType -eq $([System.Diagnostics.EventLogEntryType]::$severityLevel) }
    
  }
  catch {
    $filteredEvents = (Get-WinEvent -LogName $logName) | Where-Object { $_.level -eq $([System.Diagnostics.EventLogEntryType]::$severityLevel) }
  }
    
  # Return the count of the filtered events
  return $filteredEvents.Count
}

function Get-LogFileDetails {
  param (
    [Parameter(Mandatory = $true)]
    [string]$LogFolder,
    [Parameter(Mandatory = $true)]
    [string]$logFileName,
    [Parameter(Mandatory = $true)]
    [string]$LogEventDataFileName
    
  )
  $logFile = Join-Path -Path $LogFolder -ChildPath $logFileName
  if (Test-Path -Path $logFile) {
    $logFileDetails = Get-Item -Path $logFile
    Write-Host "Log File Details:"
    Write-Host "-----------------"
    Write-Host "Full Path: $($logFileDetails.FullName)"
    Write-Host "Size: $($logFileDetails.Length) bytes"
    Write-Host "Last Modified: $($logFileDetails.LastWriteTime)"
  }
  else {
    Write-Host "Log file does not exist."
  }
  Write-Host ""
  if (Test-Path -Path $LogEventDataFileName) {
    $logFileEventDetails = Get-Item -Path $LogEventDataFileName
    Write-Host "Log File Event Details:"
    Write-Host "-----------------"
    Write-Host "Full Path: $($logFileEventDetails.FullName)"
    Write-Host "Size: $($logFileEventDetails.Length) bytes"
    Write-Host "Last Modified: $($logFileEventDetails.LastWriteTime)"
  }
  else {
    Write-Host "Log file does not exist."
  }


}

function Format-ContinuousText {
  # Define the parameters for the function
  param (
    # The text parameter is mandatory and should be a string
    [Parameter(Mandatory = $true)]
    [string]$text
  )

  # This function is designed to transform any text into a continuous string by replacing newline characters with a space.
  # It accepts a string as input and returns a string where all newline characters (`r`n) and (`n`) are replaced with a space (" ").

  # The `-replace` operator is used to replace all newline characters with a space.
  # The result is returned as the output of the function.

  if (![string]::IsNullOrEmpty($text)) {
    $text = $text -replace "`r`n", " " # Replace carriage return and newline characters
    return $text -replace "`n", " " # Replace newline characters
  }
  else {
    return ""
  }
}
function Update-PromptData {
  <#
.SYNOPSIS
This function updates a given prompt with additional instructions for both experienced and less experienced professionals.

.DESCRIPTION
The Update-PromptData function takes an input prompt and appends additional instructions to it. These instructions are tailored for both experienced and less experienced professionals. The function returns the updated prompt.

.PARAMETER inputPrompt
The input prompt that needs to be updated. This parameter is mandatory.

.EXAMPLE
$promptAnalyze = Update-PromptData -inputPrompt $promptAnalyze
This example updates the $promptAnalyze variable.

.EXAMPLE
$promptTroubleshoot = Update-PromptData -inputPrompt $promptTroubleshoot
This example updates the $promptTroubleshoot variable.
#>
  param (
    [Parameter(Mandatory = $true)]
    [string]$inputPrompt
  )

  # Text for experienced professionals
  $experiencedProfessionalsText = "Ensure that the response is comprehensive and detailed, providing in-depth insights."
  
  # Text for less experienced professionals
  $lessExperiencedProfessionalsText = "Make sure the analysis is easy to understand, with clear explanations and step-by-step instructions."

  # Combine the input prompt with the additional instructions
  $updatedPrompt = $inputPrompt + " " + $experiencedProfessionalsText

  # Return the updated prompt
  return $updatedPrompt
}

function Get-SummarizeSession {
  param (
    [Parameter(Mandatory = $true)]
    [string]$LogFolder,
    [Parameter(Mandatory = $true)]
    [string]$logFileName,
    [bool] $Stream
  )

  Write-Host "Wait for summary..." -ForegroundColor Magenta
  Write-Host "it isn't logged" -ForegroundColor DarkGray
  Write-Host ""

  # Read the log file
  $logData = Get-Content -Path (Join-Path -Path $LogFolder -ChildPath $logFileName)

  # Initialize counters
  $userActionsCount = 0
  $systemResponsesCount = 0

  # Count the occurrences of ";user" and ";system" in the log file
  $userActionsCount = ($logData -match "; user;").Count
  $systemResponsesCount = ($logData -match "; system;").Count
  

  # Print the summary
  Write-Host "Session Summary:"
  Write-Host "Total User Actions: $userActionsCount"
  Write-Host "Total System Responses: $systemResponsesCount"
  Write-Host ""
  
  if ($Stream) {
    Write-Host "AI Summary:" -ForegroundColor Green
    # Summarize the session log data using AI
    $summary = $logData | Invoke-AIEventAnalyzer -NaturalLanguageQuery "Summarize the log data in a single paragraph to show the user what was done. Use a cheerful style. Finally, add something nice for the user."
    Write-Host ""
    # Print the summary
  }
  else {
    Write-Host "Wait for more..." -ForegroundColor Magenta -NoNewline
    # Summarize the session log data using AI
    $summary = $logData | Invoke-AIEventAnalyzer -NaturalLanguageQuery "Summarize the log data in a single paragraph to show the user what was done. Use a cheerful style. Finally, add something nice for the user."
    Write-Host ""
    # Print the summary
    Write-Host "AI Summary:" -ForegroundColor Green
    Write-Host $summary -ForegroundColor White
  }
}

function Show-Banner {
  Write-Host @'

  Welcome to the
                 _____ ______               _                        _                    
           /\   |_   _|  ____|             | |     /\               | |                   
          /  \    | | | |____   _____ _ __ | |_   /  \   _ __   __ _| |_   _ _______ _ __ 
         / /\ \   | | |  __\ \ / / _ \ '_ \| __| / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
        / ____ \ _| |_| |___\ V /  __/ | | | |_ / ____ \| | | | (_| | | |_| |/ /  __/ |   
       /_/    \_\_____|______\_/ \___|_| |_|\__/_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                                                                        __/ |             
                                                                       |___/              
                                                                  powered by PSAOAI Module
       
       voytas75; https://github.com/voytas75/AzureOpenAI-PowerShell

'@
  Write-Host @"
       This PowerShell script, Start-AIEventAnalyzer.ps1, is a tool designed to analyze Windows Event Logs using Azure's OpenAI. 
       It allows users to select a specific log and severity level, and then uses AI to analyze the events. The script provides 
       prompts to guide the user through the process, and the results are displayed in a user-friendly format. The tool is 
       particularly useful for system administrators and IT professionals who need to analyze large amounts of log data quickly 
       and efficiently.
       
"@ -ForegroundColor Blue

  Write-Host @"
       "You never know what you're gonna get with an AI, just like a box of chocolates. You might get a whiz-bang algorithm that 
       writes you a symphony in five minutes flat, or you might get a dud that can't tell a cat from a couch. But hey, that's 
       the beauty of it all, you keep feedin' it data and see what kind of miraculous contraption it spits out next."
                    
                                                                   ~ Who said that? You never know with these AIs these days... 
                                                                    ...maybe it was Skynet or maybe it was just your toaster :)

"@ -ForegroundColor DarkYellow

  Write-Host @"
       To start type 'Start-AIEventAnalyzer'


"@ -ForegroundColor White
}

# Function to get the latest version from the PowerShell Gallery
function Get-LatestVersion {
  param (
    [string]$scriptName
  )

  try {
    # Find the script on PowerShell Gallery
    $scriptInfo = Find-Script -Name $scriptName -ErrorAction Stop

    # Return the latest version
    return $scriptInfo.Version
  }
  catch {
    Write-Error "Failed to get the latest version of $scriptName from PowerShell Gallery. $_"
    return $null
  }
}

# Function to check for updates
function Check-ForUpdate {
  param (
    [string]$currentVersion,
    [string]$scriptName
  )

  # Get the latest version of the script
  $latestVersion = Get-LatestVersion -scriptName $scriptName

  if ($latestVersion) {
    # Compare versions
    if ([version]$currentVersion -lt [version]$latestVersion) {
      Write-Host " A new version ($latestVersion) of $scriptName is available. You are currently using version $currentVersion. `n`n" -BackgroundColor DarkYellow -ForegroundColor Blue
    } 
  }
  else {
    Write-Error "Unable to check for the latest version."
  }
}

Clear-Host
Show-Banner

# Check for updates as the first task
Check-ForUpdate -currentVersion "1.1" -scriptName "Start-AIEventAnalyzer"

$moduleName = "PSAOAI"
if (Get-Module -ListAvailable -Name $moduleName) {
  [void](Import-module -name PSAOAI -Force)
}
else {
  Write-Host "You need to install '$moduleName' module. USe: 'Install-Module PSAOAI'"
}
