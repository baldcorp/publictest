param (
	[Parameter(Mandatory=$false)]
	[string]$SamplePath = 'https://raw.githubusercontent.com/Yaniv-Shasha/Sentinel/master/Sample_Data/scenarios/RiskIQ_Senitnel/Events/scenario03/02-Karen_network_login.json',
	[Parameter(Mandatory=$false)]
	[string]$Format = 'csv',
	[Parameter(Mandatory=$false)]
	[string]$targetTableName = 'CommonSecurityLog',
    [Parameter(Mandatory=$false)]
    [string]$existedDCRLink = "",
	[Parameter(Mandatory=$false)]
	[string]$Replacements = '{
    "SourceIP": [
      {
        "value": "1.2.3.4",
        "replacement": "192.168.1.1"
      },
      {
        "value": "10.10.10.11",
        "replacement": "192.168.1.2"
      }
    ]
  }',
	[Parameter(Mandatory=$false)]
	[string]$startdate = '',
	[Parameter(Mandatory=$false)]
	[bool]$Test = $true
)

Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).context
# set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

$sample = (Invoke-WebRequest -Uri $SamplePath -UseBasicParsing).Content
$sampleData = if($Format -eq 'json') {$sample |ConvertFrom-Json} else {$sample |ConvertFrom-Csv}

if($sampleData[0].psobject.Properties.name -match "TimeGenerated" -and $sampleData[0].psobject.Properties.name -ne "TimeGenerated"){
    foreach ($row in $sampleData)
        {
            $tgFieldName = $($row.psobject.Properties.name -match "TimeGenerated")
            $value = $row.$tgFieldName
            $row | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $value
            $row.PSObject.Properties.Remove($tgFieldName)
        }
}elseif($sampleData[0].psObject.Properties.name -notcontains "TimeGenerated") {
    $constantdate = (Get-Date).addhours(-5)
    foreach($row in $sampleData)
    {
        $constantdate = $constantdate.AddSeconds($(Get-Random -Minimum 10 -Maximum 30))
        $row | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $constantdate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
}

if ($targetTableName -like 'Custom-*' -and (($sampleData[0] -match "/") -or ($sampleData[0] -match " "))){
    foreach($row in $sampleData)
    {
        foreach ($item in $row.psObject.Properties) {
            if ($item.name -match '/'){
                $ItemValue = $item.value
                $row.psObject.Properties.Remove($item.name)
                $row | Add-Member -MemberType NoteProperty -Name "$($item.Name.replace('/','_'))" -Value $ItemValue
            }elseif ($item.name -match ' '){
                $ItemValue = $item.value
                $row.psObject.Properties.Remove($item.name)
                $row | Add-Member -MemberType NoteProperty -Name "$($item.Name.replace(' ','_'))" -Value $ItemValue
            }
        }
    }
}

#write-output $Replacements
if ($Replacements.StartsWith("'") -and $Replacements.endswith("'") ) {
	$Replacements = $Replacements.Trim("'")
	$Replacements = $Replacements.Replace("\n", "")
	$Replacements = $Replacements.Replace("\","")
	$ReplacementsObj = $Replacements|ConvertFrom-Json
}else {
	$ReplacementsObj = $Replacements|ConvertFrom-Json
}

[string[]] $formats = @('M/d/yyyy, h:mm:ss.fff tt', 'yyyy-MM-ddTHH:mm:ss.fffZ', 'yyyy-MM-ddTHH:mm:ss.ffZ', 'yyyy-MM-ddTHH:mm:ss.fZ', 'yyyy-MM-ddTHH:mm:ssZ', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-ddTHH:mm:ss')

$now = Get-Date

$row = $sampleData[0]
$fields = $row.psObject.Properties.Name
[ref]$date = [DateTime]::MinValue
$timestampFields = @()
foreach ($field in $fields) {
  if ($null -ne $row.$field) {
    if (($row.$field.GetType().name -ne "PSCustomObject") -and ([DateTime]::TryParseExact($row.$field, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date))){
      $timestampFields += $field
    }
  }  
}
#$timestampFields = @($fields|? {[DateTime]::TryParseExact($row.$_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date)})
#$timestampFields = @($fields|? {($row.$_.GetType().name -ne "PSCustomObject") -and ([DateTime]::TryParseExact($row.$_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date))})
$tsField = $timestampFields[0]
$alldates = $sampleData.$tsField |
%{
    [ref]$rowDate = [DateTime]::MinValue
    [DateTime]::TryParseExact($_, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $rowDate) | Out-Null
    $rowDate.Value
}
$FirstDate = $alldates | Sort-Object | Select-Object -First 1
$lastDate = $alldates | Sort-Object | Select-Object -Last 1

#$tsField = $timestampFields[0]
foreach($row in $sampleData)
{

    [ref]$date = Get-Date  
    
    $dateStr = $row.$tsField 

    [DateTime]::TryParseExact($dateStr, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, $date) | Out-Null
   
    #$shift = ($lastDate - $date.Value).TotalSeconds
    
    #$newDate = $now.AddSeconds(-$shift)
	if ($startdate) {
		$shift = ($FirstDate - $date.Value).TotalSeconds
        $result = New-Object DateTime
        [DateTime]::TryParseExact($startdate, $formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$result) | Out-Null
        $newDate = $result.AddSeconds(-$shift)
    }else {
		$shift = ($lastDate - $date.Value).TotalSeconds
        $newDate = $now.AddSeconds(-$shift)
    }
    
    foreach($df in $fields|?{$_ -like "*``[*``]*"})
    {
        $newName = $df -replace '\s?\[.*\]', ''
        $value = $row.$df
        $row.PSObject.Properties.Remove($df)
        $row| Add-Member -MemberType NoteProperty -Name $newName -Value $value
        if($timestampFields -eq $df)
        {
            $timestampFields = $timestampFields -ne $df
            if(!($timestampFields -eq $newName))
            {
                $timestampFields += $newName
            }
        }
    }

    foreach($df in $timestampFields)
    {
        $row.$df = $newDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }

    
    foreach($replacementField in $ReplacementsObj.PSObject.Properties.Name)
    {
        foreach($replacement in $ReplacementsObj.$replacementField)
        {
            if(($row.$replacementField -eq $replacement.value) -or ($row.$replacementField -match $replacement.value))
            {
                $row.$replacementField = $replacement.replacement
            }
        }
    }

    $row.PSObject.Properties.Remove('_ResourceId')
    $row.PSObject.Properties.Remove('TenantId')
    $row.PSObject.Properties.Remove('MG')
}

$logData = $sampleData| Sort-Object -Property TimeGenerated | ConvertTo-Json

if($targetTableName -like 'Custom-*' -and !$Test)
{
    $wsRG = Get-AutomationVariable -Name "WorkspaceRG"
    $wsName = Get-AutomationVariable -Name "WorkspaceName"
    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $wsRG -Name $wsName
	$CustomTableName = $targetTableName.Remove(0,7)
	$TargetTable = Get-AzOperationalInsightsTable -ResourceGroupName $wsRG -WorkspaceName $wsName -TableName $CustomTableName -ErrorAction SilentlyContinue
	$columns = New-Object System.Collections.ArrayList($null)

    
    if (!$TargetTable) {
		Write-Output "Target custom table was not found, will be created ..."
        $customTable = [PSCustomObject]@{
            properties = [PSCustomObject]@{
                schema = [PSCustomObject]@{
                    name = $CustomTableName
                    columns = @()
                }
            }
        }

        if (!$existedDCRLink) {
            #usual case to create table and DCR
            
            Write-Output "SchemaLink - NO"
    
            foreach ($column in $($sampleData[0].psobject.properties | Where-Object {$_.name -notin "Type", "_ResourceId", 'MG', 'TenantId'}) ){
                if (($column.TypeNameOfValue -eq "System.String") -and ($column.Name -ne "TimeGenerated")) {
                    $columns += @{name = $($column.Name).substring(0, [System.Math]::Min(45, $($($column.Name).Length))); type = "string"}
                }else {
                    $columns += @{name = $($column.Name).substring(0, [System.Math]::Min(45, $($($column.Name).Length))); type = "datetime"}
                }
            }
            
        } else {
            Write-Output "SchemaLink - YES"
            $DCRFileSample = (Invoke-WebRequest -Uri $existedDCRLink -UseBasicParsing).Content
            $DCRFilesampleData = $DCRFileSample |ConvertFrom-Json
            #$CustomTableName = $DCRFilesampleData.Name
            foreach ($column in ($DCRFilesampleData.Properties | Where-Object { ($_.name -notin "Type", "_ResourceId", 'MG', 'TenantId') -and ($_.type -notin "Double", "SByte", "guid")})) {
                #if ($($column.Name).substring($($column.Name).length-2) -like "_*"){
                    #$column.Name = $($column.Name).substring(0,$($column.Name).Length-2)
                $column.Name = $($column.Name).substring(0, [System.Math]::Min(45, $($($column.Name).Length)))
                if ($column.Type -eq "Bool") {$column.Type = "boolean"}
                $columns += @{name = $($column.Name); type = $($column.Type.ToLower())}
            }
            #for duplicates -numerate it
            foreach($column in $columns){
                $i = 0
                if ((($columns.name -match $column.name).count -gt 1) -and ($column.name.Length -eq 45)) {
                    $duplicates = $columns | Where-Object {$_.name -eq $column.name}
                    foreach ($duplicate in $duplicates) {
                        $num = "{0:D2}" -f $i
                        $duplicate.name = $($column.Name).substring(0, [System.Math]::Min(43, $($($column.Name).Length))) + "$num"
                        #$duplicate.name
                        $i++
                    }
                }
            }
        }

        $customTable.Properties.schema.columns = $columns
        Invoke-AzRestMethod -Path $("$($ws.ResourceId)/tables/$CustomTableName"+'?api-version=2021-12-01-preview') -Method PUT -payload $($customTable|ConvertTo-Json -Depth 12)
    } else {
        Write-Output "Target custom table $CustomTableName was found, have to use existed schema"
        $getTable = (Invoke-AzRestMethod -Path $("$($targetTable.id)"+'?api-version=2021-12-01-preview') -Method GET).Content | ConvertFrom-Json
        $columnsTable = $getTable.properties.schema.columns | Select-Object -Property Name, type 
        foreach ($column in $columnsTable | Where-Object { ($_.name -notin "Type", "_ResourceId", 'MG', 'TenantId')}) {
            $columns += @{name = $($column.Name); type = $($column.Type.ToLower())}
        }
    }

    $DCRRG = Get-AutomationVariable -Name "DCRE_RG"
    $DCEname = Get-AutomationVariable -Name "DCEName"
	Write-Output "dcr rg - " $DCRRG
	Write-Output "dce name - " $DCEname
    $targetDCR = Get-AzResource -ResourceGroupName $DCRRG -ResourceType 'Microsoft.Insights/dataCollectionRules' -Name $CustomTableName -ErrorAction SilentlyContinue
    $DCEresourceID = (Get-AzResource -Name $DCEname -ResourceType "Microsoft.Insights/dataCollectionEndpoints" -ResourceGroupName $DCRRG).ResourceId
    if (!$targetDCR) {
		$CustomDCRName = $CustomTableName.Substring(0, $CustomTableName.Length -3)
		Write-Output "Target custom DCR was not found, will be created ..."
        $customDCR = [PSCustomObject]@{
            "`$schema" = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
            contentVersion = '1.0.0.0'
            parameters = [PSCustomObject]@{}
            resources = @()
			outputs = [PSCustomObject]@{
                dataCollectionRuleId = [PSCustomObject]@{
                  type = "string"
                  value = "[resourceId('Microsoft.Insights/dataCollectionRules', '$CustomDCRName')]"
                }
            }
        }
        $customDCR.resources += [PSCustomObject]@{
            type = "Microsoft.Insights/dataCollectionRules"
            name = $CustomDCRName
            location = "$($ws.location)"
            apiVersion = "2021-09-01-preview"
            properties = [PSCustomObject]@{
                dataCollectionEndpointId = $DCEresourceID
                streamDeclarations = [PSCustomObject]@{
                    'Custom-MyTableRawData' = [PSCustomObject]@{
                      columns = $columns
                    }
                }
                destinations = [PSCustomObject]@{
                      logAnalytics= @(
                          [PSCustomObject]@{
                          workspaceResourceId = $($ws.ResourceId)
                          name = "clv2ws1"
                        }
                    )
                }
                dataFlows = @(
                    [PSCustomObject]@{
                        streams = @(
                            "Custom-MyTableRawData"
                        )
                        destinations = @(
                            "clv2ws1"
                        )
                        transformKql = "source"
                        outputStream = "Custom-$CustomTableName"
                    }
                )
            }
        }
        Out-File -FilePath './customdcr.json' -InputObject $($customDCR | ConvertTo-Json -Depth 12 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_)}) -Force
        New-AzResourceGroupDeployment -ResourceGroupName $DCRRG -TemplateFile './customdcr.json'
        $DCRId =(Get-AzResource -ResourceGroupName $DCRRG -ResourceType 'Microsoft.Insights/dataCollectionRules' -Name $CustomDCRName).Properties.immutableId
    }else {
        $DCRId =(Get-AzResource -ResourceGroupName $DCRRG -ResourceType 'Microsoft.Insights/dataCollectionRules' -Name $CustomDCRName).Properties.immutableId
    }
}
else
{
	$targetTableName = $targetTableName.Split('-')[0]
	$DCRId = Get-AutomationVariable -Name "$($targetTableName)DCRId"
	#$DCEUrl = Get-AutomationVariable -Name "DCEUrl"
}

#execute log ingestion
$DCEUrl = Get-AutomationVariable -Name "DCEUrl"
$token = Get-AzAccessToken -ResourceUrl 'https://monitor.azure.com/'
$uri = "$DCEUrl/dataCollectionRules/$DCRId/streams/Custom-MyTableRawData?api-version=2021-11-01-preview"

if ($($($logData | ConvertFrom-Json).GetType()).basetype.name -eq "Object") {
    $logData = "[$logData]"
}

$chunkMaxSize = 500000
if ([System.Text.Encoding]::UTF8.GetByteCount($($sampleData|ConvertTo-Json)) -gt $chunkMaxSize) {
    write-output "The log is too big, will be split into smaller parts"
    $sampleDatachunksize = 0
    $sampleDatachunk = @()
    foreach ($sample in $sampleData) {
        $currentsize = [System.Text.Encoding]::UTF8.GetByteCount($($sample|ConvertTo-Json))
        $sampleDatachunksize = $sampleDatachunksize + $currentsize
        if (($sampleDatachunksize -lt $chunkMaxSize) -and ($sample -ne  $sampleData[-1])) {
            $sampleDatachunk += $sample
        }elseif (($sampleDatachunksize -lt $chunkMaxSize) -and ($sample -eq  $sampleData[-1])) {
            $sampleDatachunk += $sample
            $ingestResult = Invoke-RestMethod -Uri $uri -Method "Post" -Body $($sampleDatachunk | ConvertTo-Json) -Headers @{Authorization = "Bearer $($token.Token)"} -ContentType 'application/json'
            write-output $ingestResult
        }else {
            $sampleDatachunksize = $currentsize
            $ingestResult = Invoke-RestMethod -Uri $uri -Method "Post" -Body $($sampleDatachunk | ConvertTo-Json) -Headers @{Authorization = "Bearer $($token.Token)"} -ContentType 'application/json'
            $sampleDatachunk = @()
            $sampleDatachunk += $sample
            write-output $ingestResult
            Start-Sleep -seconds 2
        }
    }
} else {
    write-output "The log is Ok, do not need to split it"
    try {
        $return = Invoke-RestMethod -Uri $uri -Method "Post" -Body $logData -Headers @{Authorization = "Bearer $($token.Token)"} -ContentType 'application/json'
    } 
    catch [System.Net.WebException], [System.Net.HttpWebRequest] {
        Write-Error $_.Exception
        throw "Some errors are occurred"
    }
    catch {
        Write-Error $_.Exception
        throw "Some errors are occurred"
    }
}

#preparing the output
$AARG = Get-AutomationVariable -Name "AARG"
$AutomationJobId = $PSPrivateMetadata.JobId.Guid
$StartTime = (Get-Date).AddHours(-3)
# Loop here for a max of 90 seconds in order for the activity log to show up.
$JobInfo = @{}
$TimeoutLoop = 0
While ($JobInfo.Count -eq 0 -and $TimeoutLoop -lt 9 ) {
    $TimeoutLoop++
    $JobAcvitityLogs = Get-AzLog -ResourceGroupName $AARG -StartTime $StartTime `
    | Where-Object {$_.Authorization.Action -eq "Microsoft.Automation/automationAccounts/jobs/write"}
    # Find caller for job
    foreach ($Log in $JobAcvitityLogs)
    {
        # Get job resource
        $JobResource = Get-AzResource -ResourceId $Log.ResourceId
        if ($JobResource.Properties.jobId -eq $AutomationJobId)
        { 
            if ($JobInfo[$JobResource.Properties.jobId] -eq $null)
            {
                	$JobInfo.Add($JobResource.Properties.jobId,$log.Caller)
            }
            break
        }
    }
    # If we didn't find the running job in activity log, sleep and try again.
    if ($JobInfo.Count -eq 0) 
    {
        Start-Sleep 10
    }
}

Write-Output "Started by $($JobInfo.Values)" 

if ($logData.Length -gt 10000) {
    Write-Output "The output is too long, will be shown first and last 5000 symbols"
    write-output $logData.SubString(0, 5000)
    write-output $logData.SubString($logData.Length - 5000)
}else {
    write-output $logData
}



if($targetTableName -like 'Custom-*' -and !$Test)
{
	Get-AzResource -ResourceGroupName $DCRRG -ResourceType 'Microsoft.Insights/dataCollectionRules' -Name $CustomDCRName | Remove-AzResource -Force
}
