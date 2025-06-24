##*=============================================================
##*   AWS Security Assesment Automation
##*=============================================================
##* Licensed by Infrastructure Consulatant\ Khaled Mohamed Assasa
##* 
##* Script Steps:
##* 1- Create CloudTrail
##* 2- Enable GuardDuty
##* 3- Enable AWS Config
##* 4- Create AWS Security Hub
##* 5- Create Amazon Macie Classification
##* 6- Create Well-Architect Workload 
##* 7- Create AuditManager Assessment
##* 10- Create AWS Cognito User Pool with Default Security Configurations
##* 11- Enable AWS Inspector Service
##* 12- Enable AWS Detective Service
##* 13- Create CloudWatch alarms
##* 14- Aws Artifact
##* 15- Aws Resources Monitoring ##### Need Check (Found Error)
##*==============================================================
$Import_Modules = Import-Module AWSPowershell
$UserSecretKey  = Read-Host "Enter AWS Secret Access Key"
$UserAccessKey = Read-Host "Enter AWS Access Key ID"
$ProfileName  = Read-Host "Enter AWS profile name (leave blank for temporary session)"
$region = Read-Host "Enter AWS region (e.g. us-east-1)"
$SetCredentials = Set-AWSCredential -AccessKey $UserAccessKey -SecretKey $UserSecretKey -StoreAs $ProfileName
$setsession = Initialize-AWSDefaults -Region $region -ProfileName $ProfileName
$ANS_YES = "y","YES","yes","Y","Yes"
$ANS_NO = "n","no","N","NO","No"


function CloudTrail_fun{ 
##################################################################
##*                       START
##################################################################

#Get Account ID For CloudTrail
$account_id =(Get-STSCallerIdentity).Account
$Trail= Get-CTTrail
$Q1 = Read-Host "Do you want to create a CloudTrail (Y/N) ? Type 'Y' to create or 'N' to update"
if ($Q1 -eq "Y"){
#Get Account ID For CloudTrail
$account_id =(Get-STSCallerIdentity).Account
Write-Host ""
$Trailname = Read-Host "Enter the CloudTrail name"
##*===============================================
##*          Validate CloudTrail 
##*===============================================

$CTname= (Get-CTTrail).Name
foreach ($line in $CTname) {
    if ($line -match $Trailname ){ 
        Write-Host ""
        $Trailname = Read-Host "A trail with this name already exists. Please type another name"
    }
}
##*=======================================================
##* Create Bucket & Validation name with existing buckets 
##*=======================================================
Write-Host ""
$Request = Read-Host "Do you need to create a new bucket for CloudTrail? (Y/N)"
if ($Request -eq "Y"){
    Write-Host ""
    $name_of_bucket = Read-Host "Enter the name of the new bucket"
    $bucket_list= (get-s3bucket).BucketName
    foreach ($line in $bucket_list){
        if ($line -match $name_of_bucket){
            Write-Host ""
            $name_of_bucket = Read-Host "A bucket with the same name already exists. Please type another name"}
    }
##* Function to validate S3 bucket name
function Validate-S3BucketName {
        param ([string]$BucketName)
        
        if ($BucketName.Length -lt 3 -or $BucketName.Length -gt 63) {
            return $false
        }
        if ($BucketName -match '[^a-z0-9.-]') {
            return $false
        }
        if ($BucketName -match '^[^a-z0-9]|[^a-z0-9]$') {
            return $false
        }
        if ($BucketName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            return $false
        }
        if ($BucketName -match "bucket"-and"bucket0"-and"mybucket"-and "testbucket"-and "images"-and "data"-and "backup"-and "bucket1"-and "logs"-and "myapp"){
            return $false
        }
        return $true
    }  
 ##* Function to generate a unique bucket name
    function Generate-UniqueBucketName {
        param ([string]$name_of_bucket)
        $timestamp = (Get-Date -Format "ms")
        return "$name_of_bucket-$timestamp"
    }
    
    while (-not(Validate-S3BucketName -BucketName $name_of_bucket)){
        Write-Host ""
        Write-Warning "Failed to create bucket: $name_of_bucket. Trying another name..." 
        Write-Host ""
        $name_of_bucket = Read-Host "Enter the name of the new bucket"
    }
    $name_of_bucket = Generate-UniqueBucketName -name_of_bucket $name_of_bucket
    $bucket = New-S3Bucket -BucketName $name_of_bucket 
    Write-Host ""
    Write-Host "The bucket has been created." -ForegroundColor Green
}

##* List S3 Buckets
else {
    Write-Host ""
    Write-Host "Choose from the list of buckets that will appear below." -ForegroundColor Blue
    Write-Host ""
    Write-Host "BucketName" -ForegroundColor blue
    $buck = Get-S3Bucket
    foreach ($b in $buck){
        try{
            $x = (Get-S3BucketLocation -BucketName $b.BucketName).Value
            }catch{}
            if ([string]::IsNullOrWhiteSpace($x)){
                $x = "us-east-1"
            }
            if ($x -eq $region){
                Write-Host "===============================================" -ForegroundColor Blue
                write-host "Bucket Name : "$b.BucketName
                write-host "Region : " $x
            }

    }
    Write-Host "===============================================" -ForegroundColor Blue
    Write-Host ""
    $name_of_bucket = read-host "Enter the name of the bucket from the existing list"
    $bucket_list= (get-s3bucket).BucketName
    while ($name_of_bucket -notin $bucket_list){
        Write-Host ""
        $name_of_bucket = read-host "Please enter a valid bucket name from the existing list"
    }
}

##* Attach Policy To S3 Bucket for CloudTrail 
$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::$name_of_bucket"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$name_of_bucket/AWSLogs/$account_id/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
"@

$Policy_of_Bucket = Write-S3BucketPolicy -BucketName $name_of_bucket -Policy $policy

##*===============================================
##*        Enable CloudWatch Logs 
##*===============================================
Write-Host ""
$Enable_logs = Read-Host "Do you want to enable CloudWatch Logs? (Y/N)"
if($Enable_logs -eq "Y"){
    $permissionsPolicy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:CreateTrail",
                "cloudtrail:UpdateTrail",
                "cloudtrail:DeleteTrail",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:PutInsightSelectors"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::$name_of_bucket",
                "arn:aws:s3:::$name_of_bucket/*"
            ]
        }
    ]
}
"@

$trustPolicy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
"@
Write-Host ""
$Group_name = read-host "Entre the LogGroupName of CloudWatch "
$RoleName = $Group_name + "Role"
$PolicyName = $Group_name + "Policy"
##* Validate log group name 
$logname = (Get-CWLLogGroup).LogGroupName
    while ( $Group_name -in $logname){
        Write-Host ""
        $Group_name = Read-Host "LogGroupName already exists. Please write another name"
    }
##* Create New LogGroup for CloudWatch
$New_loggroup=New-CWLLogGroup -LogGroupName $Group_name
Write-Host ""
Write-Host "The LogGroup has been created." -ForegroundColor Green
$ARN_LogGroup=(get-CWLLogGroup -LogGroupNamePrefix $Group_name).arn

##* Create New Role for CloudWatch
$results= New-IAMRole -AssumeRolePolicyDocument $trustPolicy -RoleName $RoleName
Write-Host ""
Write-Host "The role for CloudWatch has been created." -ForegroundColor Green

##* Create policy for Role to be attached 
$Write_policy = write-IAMRolePolicy -RoleName $RoleName -PolicyDocument $permissionsPolicy -PolicyName $PolicyName
Write-Host ""
Write-Host "The policy has been attached to the role." -ForegroundColor Green
$ARN_Role=(get-IAMRole -rolename $RoleName).arn 
}

##*===============================================
##* Enable LogFileValidation for CloudTrail
##*===============================================
Write-Host ""
$validation = Read-Host "Do you want to enable log file validation? (Y/N)"
if ($validation -eq "Y"){
    $validation = $true
    Write-Host ""
    Write-Host "Log file validation has been enabled." -ForegroundColor Green
}
else {
    $validation = $false
    Write-Host ""
    Write-Host "Log file validation has been Disabled." -ForegroundColor Green
}

##*===============================================
##*      Enable MultiRegionTrail 
##*===============================================
Write-Host ""
$multi_region = read-host "Do you want to enable MultiRegionTrail ? (Y/N)"
if ($multi_region-eq "Y"){
    $multi_region= $true
    Write-Host ""
    Write-Host "MultiRegion has been Enabled." -ForegroundColor Green
}
else {
    $multi_region = $false
    Write-Host ""
    Write-Host "MultiRegion has been Disabled." -ForegroundColor Green
}

##*===============================================
##*           Create CloudTrail 
##*===============================================

#Add Tags for cloudtrail
$tags = @(@{Key='Name'; Value= $Trailname})
if($Enable_logs -eq "Y"){
    Write-Host ""
    $cloudtrail = New-CTTrail -Name $Trailname -S3BucketName $name_of_bucket -EnableLogFileValidation $validation -CloudWatchLogsLogGroupArn $ARN_LogGroup -CloudWatchLogsRoleArn $ARN_Role -TagsList $tags -IsMultiRegionTrail $multi_region
}
else{
    $cloudtrail = New-CTTrail -Name $Trailname -S3BucketName $name_of_bucket -EnableLogFileValidation $validation -TagsList $tags -IsMultiRegionTrail $multi_region
}
##*===============================================
##*          Enable  CloudTrail 
##*===============================================
Write-Host ""
$Request= read-host "Do you want to enable CloudTrail to start logging ? (Y/N)"
if ($Request -eq "Y") {
    Start-CTLogging -Name $Trailname
    Write-Host ""
    Write-Host "Logging has been enabled for the trail." -ForegroundColor Green
}

##################################################################
##*                            END
##################################################################

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "Creating a New CloudTrail Trail Has Completed" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""

 #bta3_if_sebo fe 7alo }
}







############################################################################################################################################################################
############################################################################################################################################################################
##*                                                   UPDATE
############################################################################################################################################################################
############################################################################################################################################################################


else{
    Write-Host ""
    Write-Host "Updating the trails in your account." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "Choose from the list of Trails that will appear below." -ForegroundColor Blue
    Write-Host ""
    Write-Host "list of Trails" -ForegroundColor Gray
    
    $My_Trail = Get-CTTrail
    foreach ($b in $My_Trail ){
        Write-Host "===============================================" -ForegroundColor Blue
        write-host "Trail Names:"$b.name
    }
    Write-Host "===============================================" -ForegroundColor Blue
    Write-Host ""
    $Trailname = Read-Host "Enter the name of the trail you want to update"

    ##*=======================================================
    ##* Create Bucket & Validation name with existing buckets 
    ##*=======================================================
    Write-Host ""
    $S3_Check = Read-Host "Do you want to update your S3 bucket for CloudTrail logs? (Y/N)"
    if ($S3_Check -eq "Y"){
        Write-Host ""
        $Request = read-host "Do you need to create a new bucket for CloudTrail? (Y/N)"
        if ($Request -eq "Y"){
            Write-Host ""
            $name_of_bucket =  read-host "Enter the name of the new bucket"
            $bucket_list= (get-s3bucket).BucketName
            foreach ($line in $bucket_list) {
                if ($line -match $name_of_bucket ) {
                    Write-Host ""
                     $name_of_bucket= read-host "A bucket with the same name already exists. Please type another name"}
            }
         ##* Function to validate S3 bucket name
                function Validate-S3BucketName {
                    param ([string]$BucketName)
                    
                    if ($BucketName.Length -lt 3 -or $BucketName.Length -gt 63) {
                        return $false
                    }
                    if ($BucketName -match '[^a-z0-9.-]') {
                        return $false
                    }
                    if ($BucketName -match '^[^a-z0-9]|[^a-z0-9]$') {
                        return $false
                    }
                    if ($BucketName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                        return $false
                    }
                    if ($BucketName -match "bucket"-and"bucket0"-and"mybucket"-and "testbucket"-and "images"-and "data"-and "backup"-and "bucket1"-and "logs"-and "myapp"){
                        return $false
                    }
                    return $true
                }  
                ##* Function to generate a unique bucket name
                function Generate-UniqueBucketName {
                    param ([string]$name_of_bucket)
                    $timestamp = (Get-Date -Format "ms")
                    return "$name_of_bucket-$timestamp"
                }

                while (-not(Validate-S3BucketName -BucketName $name_of_bucket)){
                    Write-Host ""
                    Write-Warning "Failed to create bucket: $name_of_bucket. Trying another name..." 
                    Write-Host ""
                    $name_of_bucket= read-host "Enter the name of the new bucket"
                }
                $name_of_bucket = Generate-UniqueBucketName -name_of_bucket $name_of_bucket
                $bucket = New-S3Bucket -BucketName $name_of_bucket 
                Write-Host ""
                Write-Host "The bucket has been created." -ForegroundColor Green
        }
        else {
            ##* List S3 Buckets
            Write-Host ""
            Write-Host "Choose from the list of buckets that will appear below." -ForegroundColor Blue
            Write-Host ""
            Write-Host "list of buckets" -ForegroundColor Blue
            $buck = Get-S3Bucket
            foreach ($b in $buck){
                try{
                    $x = (Get-S3BucketLocation -BucketName $b.BucketName).Value
                    }catch{}
                    if ([string]::IsNullOrWhiteSpace($x)){
                        $x = "us-east-1"
                    }
                    if ($x -eq $region){
                        Write-Host "===============================================" -ForegroundColor Blue
                        write-host "Bucket Name : "$b.BucketName
                        write-host "Region : " $x
                    }
            }
            Write-Host "===============================================" -ForegroundColor Blue
            $name_of_bucket = read-host "Enter the name of the bucket from the existing list"
            $bucket_list= (get-s3bucket).BucketName
            while ($name_of_bucket -notin $bucket_list){
                Write-Host ""
            $name_of_bucket = read-host "Please enter a valid bucket name from the existing list"
            }
        }

##* Attach Policy To S3 Bucket for CloudTrail 
$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::$name_of_bucket"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::$name_of_bucket/AWSLogs/$account_id/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
"@
        $Policy_of_Bucket = Write-S3BucketPolicy -BucketName $name_of_bucket -Policy $policy
        $UPdateS3 = Update-CTTrail -Name $Trailname -S3BucketName $name_of_bucket
        Write-Host ""
        Write-Host "Your S3 bucket has been updated successfully." -ForegroundColor Green
    }
##*===============================================
##* Enable CloudWatch Logs 
##*===============================================
Write-Host ""
    $Log_Check = read-host "Do you want to update your Cloudwatch logs for cloudtrail ? (Y/N) "
    if ($Log_Check -eq "Y"){
        Write-Host ""
        $X = read-host "Do you want to enable CloudWatch Logs ? (Y/N)"
if($x -eq "Y"){
    $permissionsPolicy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:CreateTrail",
                "cloudtrail:UpdateTrail",
                "cloudtrail:DeleteTrail",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:PutInsightSelectors"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::name_of_bucket",
                "arn:aws:s3:::name_of_bucket/*"
            ]
        }
    ]
}
"@

$trustPolicy = @"
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Principal": {
				"Service": "cloudtrail.amazonaws.com"
			},
			"Action": "sts:AssumeRole"
		}
	]
}
"@
Write-Host ""
$Group_name = read-host "Entre the LogGroupName of CloudWatch "
$RoleName = $Group_name + "Role"
$PolicyName = $Group_name + "Policy"
##* Validate log group name 
$logname = (Get-CWLLogGroup).LogGroupName
    while ( $Group_name -in $logname){
        Write-Host ""
        $Group_name = read-host "LogGroupName already exists. Please write another name"
    }
##* Create New LogGroup for CloudWatch
$New_loggroup=New-CWLLogGroup -LogGroupName $Group_name
Write-Host ""
Write-Host "The LogGroup has been created." -ForegroundColor Green
$ARN_LogGroup=(get-CWLLogGroup -LogGroupNamePrefix $Group_name).arn

##* Create New Role for CloudWatch
$results= New-IAMRole -AssumeRolePolicyDocument $trustPolicy -RoleName $RoleName
Write-Host ""
Write-Host "The role for CloudWatch has been created." -ForegroundColor Green

##* Create policy for Role to be attached 
$Write_policy = write-IAMRolePolicy -RoleName $RoleName -PolicyDocument $permissionsPolicy -PolicyName $PolicyName
Write-Host ""
Write-Host "The policy has been attached to the role." -ForegroundColor Green
$ARN_Role=(get-IAMRole -rolename $RoleName).arn 
Write-Host ""
Write-Host "Waiting until CloudWatch Logs are created..." -ForegroundColor Blue
Start-Sleep -Seconds 8
        $updateCT = Update-CTTrail -Name $Trailname -CloudWatchLogsLogGroupArn $ARN_LogGroup -CloudWatchLogsRoleArn $ARN_Role
        Write-Host ""
        Write-host "Your CloudWatch Logs has been updated successfully" -ForegroundColor Green
    }
}
##*===============================================
##*      Enable MultiRegionTrail 
##*===============================================
Write-Host ""
$UpdateMultiregion= read-host "Do you want to update your Multi-region trail ? (Y/N)"
if ($UpdateMultiregion -eq "Y"){
        Write-Host ""
        $multi_region = read-host "Do you want to enable MultiRegionTrail ? (Y/N)"
    if ($multi_region-eq "Y"){
        $multi_region = $true
        Write-Host ""
        Write-Host "MultiRegion has been Enabled." -ForegroundColor Green
    }
    else {
        $multi_region = $false
        Write-Host ""
        Write-Host "MultiRegion has been Disabled." -ForegroundColor Green
    }

    $updateCT = Update-CTTrail -Name $Trailname -IsMultiRegionTrail $multi_region
}

##*===============================================
##*  Enable LogFileValidation for CloudTrail
##*===============================================
Write-Host ""
$UpdateLog = read-host "Do you want to update your Trails LogFileValidation ? (Y/N)"
if ($UpdateLog -eq "Y"){
    Write-Host ""
    $validation = read-host "Do you want to enable log file validation? (Y/N)"
if ($validation -eq "Y"){
    $validation = $true
    Write-Host ""
    Write-host "Log file validation has been enabled." -ForegroundColor Green
}
else {
    $validation = $false
    Write-Host ""
    Write-host "Log file validation has been Disabled." -ForegroundColor Green
}
$updateCT = Update-CTTrail -Name $Trailname -EnableLogFileValidation $validation
}


##*===============================================
##* Enable  CloudTrail 
##*===============================================
Write-Host ""
$Updateraillogging= read-host "Do you want to update your Trail logging? (Y/N)"
if($Updateraillogging -eq "Y"){
        Write-Host ""
        $Request= read-host "Do you want to enable CloudTrail to start logging ? (Y/N)"
    if ($Request -eq "Y") {
        Start-CTLogging -Name $Trailname
        Write-Host ""
        Write-Host "The CloudTrail has been Enabled." -ForegroundColor Green
    }
    else {
        Stop-CTLogging -Name $Trailname
        Write-Host ""
        Write-Host "The CloudTrail has been Disabled." -ForegroundColor Green
    }
}









##################################################################
##*               END
##################################################################



Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "Updating your CloudTrail Trail Has Completed" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
}
}
    

function GuardDuty_fun{
    
    $account_id =(Get-STSCallerIdentity).Account
    $DetectorId = Get-GDDetectorList    
    
    if ($DetectorId -eq $NULL){
        Write-Host ""
        Write-Host "GuardDuty is not enabled in your account." -ForegroundColor Blue
        Write-Host ""
        $read = Read-Host "Do you want to enable GuardDuty? (Y/N)"
        if ($read -eq "Y"){
            # Create New GD
            $GuardDuty= New-GDDetector -enable $true -ScanEc2InstanceWithFindings_EbsVolume $true 
            # Add Tags to GD 
            $account_id =(Get-STSCallerIdentity).Account
            $DetectorId = Get-GDDetectorList 
            $arn = "arn:aws:guardduty:$($region):$($account_id):detector/$DetectorId"
            $tags = @{"Name" = "GuardDuty"}
            Add-GDResourceTag -ResourceArn $arn -tag $tags
            Write-Host ""
            Write-host "Attaching tags to GuardDuty..."-ForegroundColor Green
            Start-Sleep -Seconds 2
            Write-Host ""
            Write-host "GuardDuty has been created"-ForegroundColor Green
            ########################################
            ##* S3 Protection
            ########################################
            Write-Host ""
            $S3_Protection = read-host "Do you want to enable S3 Protection in your Protection plans ? (Y/N)"
            if ($S3_Protection -eq "Y"){
                $S3_Protection = $True
                Write-Host ""
                Write-Host "S3 Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $S3_Protection = $False
                Write-Host ""
                Write-Host "S3 Protection has been Disabled." -ForegroundColor Green
            }
            Update-GDDetector  -DetectorId $DetectorId -S3Logs_Enable $S3_Protection
            ########################################
            ##* EKS Protection
            ########################################
            Write-Host ""
            $EKS_Protection  = read-host "Do you want to enable EKS Protection in your Protection plans ? (Y/N)"
            if ($EKS_Protection -eq "Y"){
                $EKS_Protection = $True
                Write-Host ""
                Write-Host "EKS Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $EKS_Protection = $False
                Write-Host ""
                Write-Host "EKS Protection has been Disabled." -ForegroundColor Green
            }
            Update-GDDetector  -DetectorId $DetectorId -AuditLogs_Enable $EKS_Protection
            ########################################
            ##* Runtime Monitoring
            ########################################
            Write-Host ""
            $Runtime_Monitoring  = read-host "Do you want to enable Runtime Monitoring in your Protection plans ? (Y/N)"
            if($Runtime_Monitoring -eq "Y"){
                $features = @(
                New-Object Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "RUNTIME_MONITORING"
                Status = "ENABLED"}
                )
                Update-GDDetector  -DetectorId $DetectorId -Feature $features
                Write-Host ""
                Write-Host "Runtime Monitoring has been Enabled." -ForegroundColor Green
            }
            else{
                Write-Host ""
                Write-Host "Runtime Monitoring has been Disabled." -ForegroundColor Green
            }
            ########################################
            ##* Malware Protection for EC2
            ########################################
            Write-Host ""
            $Malware_Protection  = read-host "Do you want to enable Malware Protection for EC2 in your Protection plans ? (Y/N)"
            if ($Malware_Protection -eq "Y"){
                $Malware_Protection = $True
                Write-Host ""
                Write-Host "Malware Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $Malware_Protection = $False
                Write-Host ""
                Write-Host "Malware Protection has been Disabled." -ForegroundColor Green
            }
    
            Update-GDDetector  -DetectorId $DetectorId -ScanEc2InstanceWithFindings_EbsVolume $Malware_Protection
    
            ########################################
            ##* On-demand malware scan
            ########################################
            Write-Host ""
            $malware_scan =read-host "Do you want to Start On-demand malware scan  ? (Y/N)"
            if($malware_scan -eq "Y"){
                $instances = Get-EC2Instance
                if ($instances -eq $NULL){
                    Write-Host ""
                    write-host "You don't have any EC2 instances to scan in this region."
                }
                else{
                # Display instance IDs, Names, and their ARNs
                $instances.Instances | ForEach-Object {
                    $instanceId = $_.InstanceId
                    $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                    $instanceArn = "arn:aws:ec2:${region}:${account_id}:instance/${instanceId}"
                    Write-host "Instance Name: $nameTag "   -ForegroundColor Blue
                    Write-host "Instance ARN: $instanceArn" -ForegroundColor Blue
                    write-host "------------------------"
                }
                Write-Host ""
                $ResourceArn = read-host "Enter the ARN of the EC2 instance that you want to scan"
    
                while ($ResourceArn  -notin $instanceArn ){
                    Write-Host ""
                    $ResourceArn = read-host "Enter the ARN of the EC2 instance that you want to scan" 
                }
    
                $StartGDMalwareScan = Start-GDMalwareScan -ResourceArn $ResourceArn 
                Write-Host ""
                Write-host "EC2 Malware scans has been started to EC2: $nameTag" -ForegroundColor Green
                }
    
            }
    
            ########################################
            ##* RDS Protection
            ########################################
            Write-Host ""
            $RDS_Protection = read-host "Do you want to enable RDS Protection Runtime Monitoring in your Protection plans ? (Y/N)"
            if($RDS_Protection -eq "Y"){
                $RDS=@(
                New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "RDS_LOGIN_EVENTS"
                Status = "ENABLED"
                }
                )
                Update-GDDetector  -DetectorId $DetectorId -Feature $RDS
                Write-Host ""
                Write-Host "RDS Protection has been Enabled." -ForegroundColor Green
            }
            else {
                $RDS = @(
                    New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                        Name   = "RDS_LOGIN_EVENTS"
                        Status = "DISABLED"
                    }
                )
                Update-GDDetector -DetectorId $DetectorId -Feature $RDS
                Write-Host ""
                Write-Host "RDS Protection has been Disabled." -ForegroundColor Green
            }
            ########################################
            ##* Lambda Protection
            ########################################
            Write-Host ""
            $Lambda_Protection = read-host "Do you want to enable Lambda Protection in your Protection plans ? (Y/N)"
            if($Lambda_Protection -eq "Y"){
                $Lambda = @(
                (New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "LAMBDA_NETWORK_LOGS"
                Status = "ENABLED"})
                )
    
                Update-GDDetector  -DetectorId $DetectorId -Feature $Lambda 
                Write-Host ""
                Write-Host "Lambda Protection has been Enabled." -ForegroundColor Green
    
            }    

    
            ##################################################################
            ##*                            END
            ##################################################################    
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Green
            Write-Host "Creating a New GuardDuty Has Completed" -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Green
        }   

    
    }
    ##########################################################################################################################################################
    ##########################################################################################################################################################
    ##                                              UPDATE-GuardDuty
    ##########################################################################################################################################################
    ##########################################################################################################################################################    
    else {
            Write-Host "GuardDuty is enabled in your account." -ForegroundColor Blue
            ########################################
            ##* S3 Protection
            ########################################
            Write-Host ""
            $S3_Protection = read-host "Do you want to enable S3 Protection in your Protection plans ? (Y/N)"
            if ($S3_Protection -eq "Y"){
                $S3_Protection = $True
                Write-Host ""
                Write-Host "S3 Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $S3_Protection = $False
                Write-Host ""
                Write-Host "S3 Protection has been Disabled." -ForegroundColor Green
            }
            Update-GDDetector  -DetectorId $DetectorId -S3Logs_Enable $S3_Protection
            ########################################
            ##* EKS Protection
            ########################################
            Write-Host ""
            $EKS_Protection  = read-host "Do you want to enable EKS Protection in your Protection plans ? (Y/N)"
            if ($EKS_Protection -eq "Y"){
                $EKS_Protection = $True
                Write-Host ""
                Write-Host "EKS Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $EKS_Protection = $False
                Write-Host ""
                Write-Host "EKS Protection has been Disabled." -ForegroundColor Green
            }
            Update-GDDetector  -DetectorId $DetectorId -AuditLogs_Enable $EKS_Protection
            ########################################
            ##* Runtime Monitoring
            ########################################
            Write-Host ""
            $Runtime_Monitoring  = read-host "Do you want to enable Runtime Monitoring in your Protection plans ? (Y/N)"
            if($Runtime_Monitoring -eq "Y"){
                $features = @(
                New-Object Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "RUNTIME_MONITORING"
                Status = "ENABLED"}
                )
                Update-GDDetector  -DetectorId $DetectorId -Feature $features
                Write-Host ""
                Write-Host "Runtime Monitoring has been Enabled." -ForegroundColor Green
            }
            else{
                Write-Host ""
                Write-Host "Runtime Monitoring has been Disabled." -ForegroundColor Green
            }

            ########################################
            ##* Malware Protection for EC2
            ########################################
            Write-Host ""
            $Malware_Protection  = read-host "Do you want to enable Malware Protection for EC2 in your Protection plans ? (Y/N)"
            if ($Malware_Protection -eq "Y"){
                $Malware_Protection = $True
                Write-Host ""
                Write-Host "Malware Protection has been Enabled." -ForegroundColor Green
            }
            else{
                $Malware_Protection = $False
                Write-Host ""
                Write-Host "Malware Protection has been Disabled." -ForegroundColor Green
            }
    
            Update-GDDetector  -DetectorId $DetectorId -ScanEc2InstanceWithFindings_EbsVolume $Malware_Protection
    
            ########################################
            ##* On-demand malware scan
            ########################################
            Write-Host ""
            $malware_scan =read-host "Do you want to Start On-demand malware scan  ? (Y/N)"
            if($malware_scan -eq "Y"){
                $instances = Get-EC2Instance
                if ($instances -eq $NULL){
                    Write-Host ""
                    Write-Host "You don't have any EC2 instances to scan in this region." -ForegroundColor Blue
                }
                else{
                # Display instance IDs, Names, and their ARNs
                $instances.Instances | ForEach-Object {
                    $instanceId = $_.InstanceId
                    $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                    $instanceArn = "arn:aws:ec2:${region}:${account_id}:instance/${instanceId}"
                    Write-host "Instance Name: $nameTag "   -ForegroundColor Blue
                    Write-host "Instance ARN: $instanceArn" -ForegroundColor Blue
                    write-host "------------------------"
                }
                Write-Host ""
                $ResourceArn = read-host "Enter the ARN of the EC2 instance that you want to scan"
    
                while ($ResourceArn  -notin $instanceArn ){
                    Write-Host ""
                    $ResourceArn = read-host "Enter the ARN of the EC2 instance that you want to scan" 
                }
    
                $StartGDMalwareScan = Start-GDMalwareScan -ResourceArn $ResourceArn 
                Write-Host ""
                Write-host "EC2 Malware scans has been started to EC2: $nameTag" -ForegroundColor Green
                }
            }
            ########################################
            ##* RDS Protection
            ########################################
            Write-Host ""
            $RDS_Protection = read-host "Do you want to enable RDS Protection Runtime Monitoring in your Protection plans ? (Y/N)"
            if($RDS_Protection -eq "Y"){
                $RDS=@(
                New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "RDS_LOGIN_EVENTS"
                Status = "ENABLED"
                }
                )
                Update-GDDetector  -DetectorId $DetectorId -Feature $RDS
                Write-Host ""
                Write-Host "RDS Protection has been Enabled." -ForegroundColor Green
            }
            else {
                $RDS = @(
                    New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                        Name   = "RDS_LOGIN_EVENTS"
                        Status = "DISABLED"
                    }
                )
                Write-Host ""
                Write-Host "RDS Protection has been Disabled." -ForegroundColor Green
                Update-GDDetector -DetectorId $DetectorId -Feature $RDS
            }
            
            ########################################
            ##* Lambda Protection
            ########################################
            Write-Host ""
            $Lambda_Protection = read-host "Do you want to enable Lambda Protection in your Protection plans ? (Y/N)"
            if($Lambda_Protection -eq "Y"){
                $Lambda = @(
                (New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "LAMBDA_NETWORK_LOGS"
                Status = "ENABLED"})
                )
    
                Update-GDDetector  -DetectorId $DetectorId -Feature $Lambda 
                Write-Host ""
                Write-Host "Lambda Protection has been Enabled." -ForegroundColor Green
    
            }    
            else {
                $Lambda = @(
                (New-Object -TypeName Amazon.GuardDuty.Model.DetectorFeatureConfiguration -Property @{
                Name = "LAMBDA_NETWORK_LOGS"
                Status = "DISABLED"})
                )
    
                Update-GDDetector  -DetectorId $DetectorId -Feature $Lambda 
                Write-Host ""
                Write-Host "Lambda Protection has been Disabled." -ForegroundColor Green

            }
        ##################################################################
        ##*                            END
        ##################################################################
    
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Green
        Write-Host          "GuardDuty has been updated" -ForegroundColor Green
        Write-Host "===============================================" -ForegroundColor Green
        Write-Host ""
        
    }
    
    ####
}


function AWSConfig_fun{ 
##################################################################
##*                       START
##################################################################


#Get Account ID For AWS-Config
$account_id =(Get-STSCallerIdentity).Account

##*=======================================================
##* Start Recording For AWS-config
##*=======================================================
$START_config = Read-Host "Do you need to start recording for AWS Config? (Y/N)"
if($START_config -eq "Y"){
    $recorderName = "default"
    $Enable_recording = Start-CFGConfigurationRecorder -ConfigurationRecorderName $recorderName
    Write-Host ""
    Write-Host "The Recoding has been started" -ForegroundColor Green
}
##*=======================================================
##* Create Bucket & Validation name with existing buckets 
##*=======================================================
Write-Host ""
$Request = Read-Host "Do you want to create a new bucket for AWS Config? (Y/N)"
if ($Request -eq "Y"){
    Write-Host ""
    $name_of_bucket = Read-Host "Enter the name of the new bucket"
    $bucket_list= (get-s3bucket).BucketName
    foreach ($line in $bucket_list){
        if ($line -match $name_of_bucket){
            Write-Host ""
             $name_of_bucket= read-host "A bucket with the same name already exists. Please enter another name."}
    }
 ##* Function to validate S3 bucket name
 function Validate-S3BucketName {
        param ([string]$BucketName)
        
        if ($BucketName.Length -lt 3 -or $BucketName.Length -gt 63) {
            return $false
        }
        if ($BucketName -match '[^a-z0-9.-]') {
            return $false
        }
        if ($BucketName -match '^[^a-z0-9]|[^a-z0-9]$') {
            return $false
        }
        if ($BucketName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            return $false
        }
        if ($BucketName -match "bucket"-and"bucket0"-and"mybucket"-and "testbucket"-and "images"-and "data"-and "backup"-and "bucket1"-and "logs"-and "myapp"){
            return $false
        }
        return $true
    }  
 ##* Function to generate a unique bucket name
    function Generate-UniqueBucketName {
        param ([string]$name_of_bucket)
        $timestamp = (Get-Date -Format "ms")
        return "$name_of_bucket-$timestamp"
    }
    
    while (-not(Validate-S3BucketName -BucketName $name_of_bucket)){
        Write-Host ""
        Write-Warning "Failed to create bucket: $name_of_bucket. Trying another name..." 
        Write-Host ""
        $name_of_bucket = Read-Host "Enter the name of the new bucket"
    }
    $name_of_bucket = Generate-UniqueBucketName -name_of_bucket $name_of_bucket
    $bucket = New-S3Bucket -BucketName $name_of_bucket 
    Write-Host ""
    Write-Host "The bucket has been created." -ForegroundColor Green
    Write-Host ""
Write-Host "Waiting until the policy is attached to the S3 bucket..." -ForegroundColor Blue
#======================================================
##* Attach Policy To S3 Bucket for CloudTrail 
#======================================================
$policy = @"
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSConfigBucketPermissionsCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::$name_of_bucket",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceAccount": "$account_id"
                }
            }
        },
        {
            "Sid": "AWSConfigBucketExistenceCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::$name_of_bucket",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceAccount": "$account_id"
                }
            }
        },
        {
            "Sid": "AWSConfigBucketDelivery",
            "Effect": "Allow",
            "Principal": {
                "Service": "config.amazonaws.com"
            },
            "Action": "s3:PutObject",
          "Resource":"arn:aws:s3:::$name_of_bucket/AWSLogs/$account_id/Config/*",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceAccount": "$account_id",
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
"@
$Policy_of_Bucket = Write-S3BucketPolicy -BucketName $name_of_bucket -Policy $policy

##*=======================================================
##* Attach S3 bucket to Delivery method for AWS-Config 
##*=======================================================
$deliveryChannelName = "default"
Write-CFGDeliveryChannel -DeliveryChannelName $deliveryChannelName -DeliveryChannel_S3BucketName $name_of_bucket
Write-Host ""
Write-Host "The S3 bucket has been successfully attached as the delivery method for AWS Config." -ForegroundColor Green
}

##################################################################
##*                            END
##################################################################
Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "Creating a  AWs Config Has Completed" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""    
}

function securityHub_fun{ 
    ##################################################################
    ##*                       START
    ##################################################################

    ##*=======================================================
    ##* Enable Securityhub
    ##*=======================================================
    $Q12 = Read-Host "Would you like to enable Securityhub in your account ? (Y/N)"
    if($Q12 -eq "Y"){
        try{
            Enable-SHUBSecurityHub 
            Write-Host ""
            Write-host "SecurityHub has been enabled in your account." -ForegroundColor Green
        }catch{
            Write-Host ""
            Write-host "SecurityHub has already been enabled in your account." -ForegroundColor Blue
        }
    }
    ##*=======================================================
    ##* Enable config for security hub
    ##*=======================================================
    #Before you can enable Security Hub standards and controls, you must first enable resource recording in AWS Config
    Write-Host ""
    Write-Warning "We must first enable resource recording in AWS Config Before enabling Security Hub standards  "
    Write-Host ""
    $Q2 = Read-Host "Would you like to enable  Reccording in AWS Config? (Y/N)"
    if ($Q2 -eq "Y"){
        Write-Host ""
        Write-Host "Enabling AWS Config is in progress..." -ForegroundColor Blue
        $recorderName = "default"
        $Enable_recording = Start-CFGConfigurationRecorder -ConfigurationRecorderName $recorderName
        Write-Host ""
        Write-Host "AWS Config recording has started" -ForegroundColor Green
    }

    Write-Host ""
    $Q1 = Read-Host "Would you like to enable security standards for securityhub ? (Y/N)"
    if($q1 -eq "Y"){
        ##*=======================================================
        ##* Security standards
        ##*=======================================================
        # Define the StandardsSubscriptionRequest object
        Write-Host ""
        $AWS_Foundational= read-host "Do You Need To Enable AWS Foundational Security Best Practices v1.0.0 Standard? (Y/N)"
        if($AWS_Foundational -eq "Y"){
            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:$region::standards/aws-foundational-security-best-practices/v/1.0.0"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsInput.Add("Version", "1.0.0") 
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_AWS_Foundational= Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "AWS Foundational Security Best Practices v1.0.0 has been enabled." -ForegroundColor Green
        }
        Write-Host ""
        $CISv1_2_0 = read-host "Do You Need To Enable CIS AWS Foundations Benchmark v1.2.0 Standard? (Y/N)"
        if($CISv1_2_0 -eq "Y"){

            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_CISv1_2_0 = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "CIS AWS Foundations Benchmark v1.2.0 has been enabled." -ForegroundColor Green

        }
        Write-Host ""
        $CISv3_2_0 = read-host "Do You Need To Enable CIS AWS Foundations Benchmark v3.0.0 Standard? (Y/N)"
        if($CISv3_2_0 -eq "Y"){

            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:$region::standards/cis-aws-foundations-benchmark/v/3.0.0"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_CISv3_2_0 = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "CIS AWS Foundations Benchmark v3.0.0 has been enabled." -ForegroundColor Green

        } 
        Write-Host ""
        $PCI_DSS_v3_2_1 = read-host "Do You Need To Enable PCI DSS v3.2.1 Standard? (Y/N)"
        if($PCI_DSS_v3_2_1 -eq "Y"){

            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:$region::standards/pci-dss/v/3.2.1"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_PCI_DSS_v3_2_1 = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "PCI DSS v3.2.1 has been enabled." -ForegroundColor Green

        }
        Write-Host ""
        $CISv1_4_0 = read-host "Do You Need To Enable CIS AWS Foundations Benchmark v1.4.0 ? (Y/N)"
        if($CISv1_4_0 -eq "Y"){

            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:$region::standards/cis-aws-foundations-benchmark/v/1.4.0"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_CISv1_4_0 = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "CIS AWS Foundations Benchmark v1.4.0 has been enabled." -ForegroundColor Green
        }
        Write-Host ""
        $NIST_Revision_5 = read-host "Do You Need To Enable NIST Special Publication 800-53 Revision 5 ? (Y/N)"
        if($NIST_Revision_5  -eq "Y"){

            $standardsSubscriptionRequest = New-Object Amazon.SecurityHub.Model.StandardsSubscriptionRequest
            $standardsSubscriptionRequest.StandardsArn = "arn:aws:securityhub:$region::standards/nist-800-53/v/5.0.0"
            $standardsInput = New-Object 'System.Collections.Generic.Dictionary[String,String]'
            $standardsSubscriptionRequest.StandardsInput = $standardsInput
            $standardsSubscriptionRequests = @($standardsSubscriptionRequest)
            $Enable_NIST_Revision_5 = Enable-SHUBStandardsBatch -StandardsSubscriptionRequest $standardsSubscriptionRequests
            Write-Host ""
            Write-Host "NIST Special Publication 800-53 Revision 5 has been enabled." -ForegroundColor Green

        }
    }


    ##################################################################
    ##*                            END
    ##################################################################



    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "Creating a  Securityhub Has been Completed" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
}


function Macie_fun {
        ###*===============================================#
        # Create Classification Job in your account
        ###*===============================================#
        try{
        Enable-MAC2Macie
        }catch{
            Write-host "Macie has already been enabled" -ForegroundColor yellow
            Write-Host " "
        }
        do{ 
        $req1 = read-host "Do You Want Create New Bucket ? (Y/N)"
        Write-Host " "
        if($req1 -eq "Y"){
            function Validate-S3BucketName {
                param ([string]$BucketName)
                
                if ($BucketName.Length -lt 3 -or $BucketName.Length -gt 63) {
                    return $false
                }
                if ($BucketName -match '[^a-z0-9.-]') {
                    return $false
                }
                if ($BucketName -match '^[^a-z0-9]|[^a-z0-9]$') {
                    return $false
                }
                if ($BucketName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                    return $false
                }
                if ($BucketName -match "bucket"-and"bucket0"-and"mybucket"-and "testbucket"-and "images"-and "data"-and "backup"-and "bucket1"-and "logs"-and "myapp"){
                    return $false
                }
                return $true
            }  
            $bucketName = read-host "Please Enter Name of Bucket"
            Write-Host " "
            while ((Validate-S3BucketName -BucketName $bucketName) -ne $true) {
                Write-Host "Bucket name invalid " -ForegroundColor Red
                Write-Host " "
                $bucketName = read-host "Please Enter Name of Bucket" 
                Write-Host " "
            }
            $bucket = New-S3Bucket -BucketName $bucketName -Region $region
            Write-host "The New Bucket has been created" -ForegroundColor green
            Write-Host " "
        
        
        }else{
            
            Write-Host "Buckets :" -ForegroundColor Blue
            $buck = Get-S3Bucket
            foreach ($b in $buck){
                try{
                $x = (Get-S3BucketLocation -BucketName $b.BucketName).Value
                }catch{}
                if ([string]::IsNullOrWhiteSpace($x)){
                    $x = "us-east-1"
                }
                if ($x -eq $region){
                    Write-Host "===============================================" -ForegroundColor Blue
                    write-host "Bucket Name : "$b.BucketName
                    write-host "Region : " $x
                }
                
                   
            }
            Write-Host " "
            $bucketName = read-host "Select the Bucket Do You need to use (Must the bucket in your region)"
            Write-Host " "
            
        }
        
        
        $login = Write-S3BucketLogging -BucketName $bucketName -LoggingConfig_TargetBucketName $bucketName -LoggingConfig_TargetPrefix "logs/"
        
        $version = Write-S3BucketVersioning -BucketName $bucketName -VersioningConfig_Status Enabled
        
        $accountId = (Get-STSCallerIdentity).account
        
        
        $s3BucketDefinition = New-Object Amazon.Macie2.Model.S3BucketDefinitionForJob
        $s3BucketDefinition.AccountId = $accountId
        $s3BucketDefinition.Buckets = $bucketName
        
        $name = read-host "Please enter name of classification"
        Write-Host " "
        while ($name -in (Get-MAC2ClassificationJobList).name) {
            $name = read-host "enter another name of classification"
            Write-Host " "
        }
        $JobType = "ONE_TIME"
        
        $classificationJob = New-MAC2ClassificationJob -JobType $JobType -name $name -S3JobDefinition_BucketDefinition $s3BucketDefinition
        
        Write-Host "===============================================" -ForegroundColor Green
        Write-host "Calsssfication Job has been created " -ForegroundColor green
        Write-Host "===============================================" -ForegroundColor Green
        Write-Host " "
        $q2 = Read-Host "Do You Want To create another classification job ? (Y/N)"
        Write-Host " "
        }while ($q2 -eq "Y")
        
}


function WellArchitect_fun {
    ###*===============================================#
    # Create Workload in your account
    ###*===============================================#
    $WorkloadName = Read-Host "Please Enter Workload Name"
    Write-Host " "
    while(($WorkloadName -in ((Get-WATWorkloadList).WorkloadName)) -or ($workloadName.Length -lt 3)){
        Write-Host "A workload name already exists or less than 3 character" -ForegroundColor red
        $WorkloadName = Read-Host "Please Enter Workload Name"   
        Write-Host " "
    }
    $Environment = Read-Host "Please choose The environment (Production/Pre-production)"
    Write-Host " "
    if($Environment -ne "Production"){
        $Environment = "PREPRODUCTION"
    }else{
        $Environment = "PRODUCTION"
    }
    $accountId = (Get-STSCallerIdentity).account
    $ReviewOwner = read-host "Please Enter your mail that will be the Review Owner"
    Write-Host " "
    Write-Host "Lenses : " -ForegroundColor Blue
    (Get-WATLenseList).LensAlias
    $Lenses = @()
    do{
    Write-Host " "    
    $Lenses += read-host "Select the Lense"
    Write-Host " "
    $req = read-host "Do you want another Lense? (Y/N)"
    Write-Host " "
    }while($req -eq "Y")
    
    
    $Workload = New-WATWorkload -WorkloadName $WorkloadName -Description "Workload of $WorkloadName" -Environment $Environment -AccountIds $accountId -AwsRegions $region -PillarPriorities @("security", "reliability", "performance", "costOptimization", "operationalExcellence") -Lenses $Lenses -ReviewOwner $ReviewOwner
    
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "The Workload Has been created" -ForegroundColor green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host " "
    
}


function AuditManager_fun {
###*===============================================#
# Create The Audit Manager Assessment in your account
###*===============================================#
    $assumeRolePolicyDocument = @"
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "auditmanager.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
"@
    
    
    $roleName = "AuditManagerRole"
    try{
    $newRole = New-IAMRole -RoleName $roleName -AssumeRolePolicyDocument $assumeRolePolicyDocument
    }
    catch{
      write-host "This role alredy exist" -ForegroundColor red
      Write-Host " "
    }
    $policyDocument = @"
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "auditmanager:*",
            "s3:*",
            "ec2:Describe*",
            "iam:List*",
            "organizations:List*"
          ],
          "Resource": "*"
        }
      ]
    }
"@
    
    # Create IAM policy for Audit Manager
    $policyName = "AuditManagerPolicy"
    try{
    $policyArn = (New-IAMPolicy -PolicyName $policyName -PolicyDocument $policyDocument).Arn
    }
    catch{
      write-host "This Policy alredy exist" -ForegroundColor red
      Write-Host " "
    }
    try{
    Register-IAMRolePolicy -RoleName $roleName -PolicyArn $policyArn
    }
    catch{
      write-host "This Policy alredy registered" -ForegroundColor red
      Write-Host " "
    }
    $frameworkType = "Standard"
    $frameworkList = Get-AUDMAssessmentFrameworkList -FrameworkType $frameworkType
    Write-Host "Framework List : " -ForegroundColor blue
    foreach ($framework in $frameworkList) {
        Write-Output "Framework Name: $($framework.Name)"
        Write-Output "Framework ID: $($framework.Id)"
        Write-Output "-----------------------------------"
    }
    $frameworkId = read-host "Enetr The Framework ID"
    Write-Host " "
    $assessmentName = "MyAuditManagerAssessment"
    $accountId = (Get-STSCallerIdentity).account
    
    $account = New-Object -TypeName Amazon.AuditManager.Model.AWSAccount
    $account.Id = $accountId
    $account.EmailAddress = read-host "Enter yor Email ex(example@example.com)"
    Write-Host " "
    $account.Name = "MyAWSAccount"
    
    $scope_AwsAccount = @($account)
    
    $req1 = read-host "Do You Want Create New Bucket for New Assessment ? (Y/N) "
    Write-Host " "
    if($req1 -eq "Y"){
        function Validate-S3BucketName {
            param ([string]$BucketName)
            
            if ($BucketName.Length -lt 3 -or $BucketName.Length -gt 63) {
                return $false
            }
            if ($BucketName -match '[^a-z0-9.-]') {
                return $false
            }
            if ($BucketName -match '^[^a-z0-9]|[^a-z0-9]$') {
                return $false
            }
            if ($BucketName -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                return $false
            }
            if ($BucketName -match "bucket"-and"bucket0"-and"mybucket"-and "testbucket"-and "images"-and "data"-and "backup"-and "bucket1"-and "logs"-and "myapp"){
                return $false
            }
            return $true
        }  
        $bucketName = read-host "Please Enter Name of Bucket"
        Write-Host " "
        while ((Validate-S3BucketName -BucketName $bucketName) -ne $true) {
            Write-Host "Bucket name invalid " -ForegroundColor Red
            Write-Host " "
            $bucketName = read-host "Please Enter Name of Bucket" 
            Write-Host " "
        }
        $bucket = New-S3Bucket -BucketName $bucketName -Region $region
        Write-host "The New Bucket has been created" -ForegroundColor green
        Write-Host " "
    
    
    }else{
        
      Write-Host "Buckets :" -ForegroundColor Blue
      $buck = Get-S3Bucket
      foreach ($b in $buck){
        try{
            $x = (Get-S3BucketLocation -BucketName $b.BucketName).Value
            }catch{}
            if ([string]::IsNullOrWhiteSpace($x)){
                $x = "us-east-1"
            }
            if ($x -eq $region){
                Write-Host "===============================================" -ForegroundColor Blue
                write-host "Bucket Name : "$b.BucketName
                write-host "Region : " $x
            }
             
      }
      Write-Host " "
        $bucketName = read-host "Select the Bucket Do You need to use"
        Write-Host " "
        
    }
    $reportsDestination = New-Object -TypeName Amazon.AuditManager.Model.AssessmentReportsDestination
    $reportsDestination.DestinationType = "S3"
    $reportsDestination.Destination = "s3://"+"$bucketName"
    
    $role1 = New-Object -TypeName Amazon.AuditManager.Model.Role
    $role1.RoleType = "PROCESS_OWNER"
    $role1.RoleArn = "arn:aws:iam::"+"$accountId"+":role/AuditManagerRole"
    
    
    $roles = @($role1)
    
    $assessment = New-AUDMAssessment -Name $assessmentName -FrameworkId $frameworkId -Scope_AwsAccount $scope_AwsAccount -Roles $roles -AssessmentReportsDestination_Destination $reportsDestination.Destination -AssessmentReportsDestination_DestinationType $reportsDestination.DestinationType -Tags @{
        "Environment" = "Production"
    }
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "The Audit Manager Assessment has been created" -ForegroundColor green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host " "
    
}



function Detective_fun {
    do {
        $ANS_YES = "y","yes","Yes","YES","Y","yES","yeS","YeS","yEs","YEs","yEs","YeS","yES","yEs","YES","yES","YeS"
        $ANS_NO = "n","no","No","NO","N","nO","nO","No","nO","NO","nO"
        write-Host ""
        $DTC = Read-Host "Do you want to enable AWS Detective ? (Y) | (N)"
        if ($DTC -in $ANS_YES) {
            write-Host ""
            write-Host "##############################################################" -ForegroundColor DarkCyan
            write-Host "           Checking if the Detective is enabled or not ......" -ForegroundColor yellow
            write-Host "##############################################################" -ForegroundColor DarkCyan
            write-Host  ""
            $accountId = Get-STSCallerIdentity | Select-Object -ExpandProperty Account
            $Existing_account  = Get-DTCTOrganizationAdminAccountList | Where-Object {$_.AccountId -eq $accountId} | select-object -ExpandProperty AccountId
            if ($accountId -eq $Existing_account) {
                write-Host ""
                write-Host "######################################################"
                write-Host "             The Account ID is Exists !" -ForegroundColor green
                write-Host "######################################################"
                write-Host ""
            }else{
                write-Host ""
                write-Host "######################################################"
                write-Host "            The Account ID is not Exists !" -ForegroundColor red
                write-Host "######################################################"
                write-Host ""
                
                $Enable_Detective = Read-Host "Do you want to Enable AWS  Detective ? (Y) | (N)"
                if ($Enable_Detective -in $ANS_YES) {
                    $enable_service_dtc = Enable-DTCTOrganizationAdminAccount -AccountId $accountId
                    write-Host ""
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host "             Detective Enabled Successfully " -ForegroundColor green
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host ""
                }elseif ($Enable_Detective -in $ANS_NO) {
                    write-Host ""
                    write-Host "###########################################################################" -ForegroundColor Blue
                    Write-Host "      You have selected not to Enable Detective !" -ForegroundColor yellow 
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host ""
                } else {
                    write-Host ""
                    write-Host "###########################################################################" -ForegroundColor Blue
                    Write-Host "                Invalid choice " -ForegroundColor red
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host ""
                }
            }
        }elseif ($DTC -in $ANS_NO) {
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "              You have selected not to Enable Detective !" -ForegroundColor yellow
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        } else {
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "                         Invalid choice " -ForegroundColor red
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        }
        write-Host ""
        $Create_investigation = Read-Host "Do you want to create a Investigation ? (Y) | (N)"
        write-Host "==========================================================================="
        if($Create_investigation -in $ANS_YES){
            $Entity_choice = Read-Host "Please Select Entity Arn is For User Or Role or Press Enter to Skip ?"
            if ($Entity_choice -eq "User") {
                $User_arn = Get-IAMUserList | Where-Object {$_.Path -eq "/"}  |Select-Object -Property UserName , Arn 
                $DTC_graph_user = New-DTCTGraph
                write-Host ""
                write-Host "####################################################################################################################"
                write-Host "                                        Users Arn List" -ForegroundColor yellow
                write-Host "####################################################################################################################"
                write-Host""
                $u = 1
                foreach ($User in $User_arn) {
                    write-Host "----------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                    Write-Host " || UserName: $($User.UserName) || User Arn : $($User.Arn) || " -ForegroundColor yellow 
                    write-Host "----------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                    $u++
                }
                write-Host ""
                $user_selection = Read-Host "Enter the User Arn to Create Investigation ?"
                write-Host "====================================================================================================="
                write-Host ""
                $Scope_Start_time_USER = [String](Read-Host "Enter the Start Time of the Investigation (Example: 2024-06-18T16:00:00)?")
                write-Host "====================================================================================================="
                write-Host ""
                $Scope_End_time_user = [String](Read-Host "Enter the End Time of the Investigation (Example: 2024-07-18T16:00:00)?")
                write-Host "====================================================================================================="
                write-Host ""
                $user_investigation = Start-DTCTInvestigation -EntityArn $user_selection -GraphArn $DTC_graph_user  -ScopeStartTime $Scope_Start_time_USER -ScopeEndTime $Scope_End_time_user
                write-Host "####################################################################################################" -ForegroundColor DarkCyan
                write-Host "                        Investigation Created Successfully For UserName" -ForegroundColor green
                write-Host "####################################################################################################" -ForegroundColor DarkCyan
            }elseif($Entity_choice -eq "Role"){
                $RoleName_Arn = Get-IAMRoleList | Where-Object {$_.Path -eq "/"}  |Select-Object -Property RoleName , Arn 
                $DTC_graph_role = New-DTCTGraph
                write-Host ""
                write-Host "####################################################################################################"
                write-Host "                                  Role Arn List" -ForegroundColor yellow
                write-Host "####################################################################################################"
                write-Host""
                $r = 1
                foreach ($Role in $RoleName_Arn) {
                    write-Host "----------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                    Write-Host " || Role Name: $($Role.RoleName) || Role Arn : $($Role.Arn) || " -ForegroundColor yellow 
                    write-Host "----------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                    $r++
                }
                write-Host ""
                $Role_selection = Read-Host "Enter the Role Arn to Create Investigation ?"
                write-Host "====================================================================================================="
                write-Host ""
                $Scope_Start_time_role = [String](Read-Host "Enter the Start Time of the Investigation (Example: 2024-06-18T16:00:00)?")
                write-Host "====================================================================================================="
                write-Host ""
                $Scope_End_time_role = [String](Read-Host "Enter the End Time of the Investigation (Example: 2024-07-18T16:00:00)?")
                write-Host "====================================================================================================="
                write-Host ""
                $role_investigation = Start-DTCTInvestigation -EntityArn $Role_selection -GraphArn $DTC_graph_role  -ScopeStartTime $Scope_Start_time_role -ScopeEndTime $Scope_End_time_role
                write-Host "####################################################################################################" -ForegroundColor DarkCyan
                write-Host "                      Investigation Created Successfully For Role Resource " -ForegroundColor green
                write-Host "####################################################################################################" -ForegroundColor DarkCyan
    
            }elseif ($Entity_choice -eq "Skip") {
                write-Host ""
                write-Host "###########################################################################" -ForegroundColor Blue 
                Write-Host "                        Operation Skipped  " -ForegroundColor red
                write-Host "###########################################################################" -ForegroundColor Blue
                write-Host ""
            }else{
                write-Host ""
                write-Host "###########################################################################" -ForegroundColor Blue 
                Write-Host "                     Invalid choice For Entity " -ForegroundColor red
                write-Host "###########################################################################" -ForegroundColor Blue
                write-Host ""
            }
    
        }elseif($Create_investigation -in $ANS_NO){
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "           You have selected not to Proceed with Investigation !" -ForegroundColor yellow
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        }else{
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "                          Invalid choice " -ForegroundColor red
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        }
    
    }while(([String]::IsNullOrEmpty($DTC ) -or [String]::IsNullOrWhiteSpace(($DTC))))
}

function inspector_fun {
    do {
        $ANS_YES = "y","yes","Yes","YES","Y","yES","yeS","YeS","yEs","YEs","yEs","YeS","yES","yEs","YES","yES","YeS"
        $ANS_NO = "n","no","No","NO","N","nO","nO","No","nO","NO","nO"
        $Inspector = Read-Host "Do you want to Proceed with AWS Inspector ? (Y) | (N)"
        if ($Inspector -in $ANS_YES) {
            write-Host ""
            write-Host "##################################################################################" -ForegroundColor DarkCyan
            write-Host "              Checking if the Inspector is enabled or not ........." -ForegroundColor yellow
            write-Host "##################################################################################" -ForegroundColor DarkCyan
            write-Host ""
            $accountId_inspector = Get-STSCallerIdentity | Select-Object -ExpandProperty Account 
            $Existing_account_inspector  = Get-INS2DelegatedAdminAccountList | Where-Object {$_.AccountId -eq $accountId_inspector} | select-object -ExpandProperty AccountId 
            if ($Existing_account_inspector -eq $accountId_inspector) {
                write-Host ""
                write-Host "####################################################################"
                write-Host "             The Account ID is Exists On Inspector Service !" -ForegroundColor green
                write-Host "####################################################################"
                write-Host ""
            }else{
                write-Host ""
                write-Host "########################################################################"
                write-Host "             The Account ID is not Exists On Inspector Service !" -ForegroundColor red
                write-Host "########################################################################"
                write-Host ""
                $Enable_inspector = Read-Host "Do you want to Enable AWS Inspector ? (Y) | (N)" 
                if ($Enable_inspector -in $ANS_YES) {
                    $Enable_inspector_service = Enable-INS2DelegatedAdminAccount -DelegatedAdminAccountId $accountId_inspector
                    write-Host ""
                    write-Host "#####################################################################################" -ForegroundColor Blue
                    write-Host "                Inspector Service Enabled Successfully " -ForegroundColor green
                    write-Host ""
                    write-Host "    Go To AWS Console and Activate Deep Inspection to Enable Inspector Service" -ForegroundColor yellow
                    write-Host "#####################################################################################" -ForegroundColor Blue
                    write-Host ""
                }elseif ($Enable_inspector -in $ANS_NO) {
                    write-Host ""
                    write-Host "###########################################################################" -ForegroundColor Blue
                    Write-Host "        You have selected To Keep Current Status Inspector Service !" -ForegroundColor yellow 
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host ""
                } else {
                    write-Host ""
                    write-Host "###########################################################################" -ForegroundColor Blue
                    Write-Host "                Invalid choice " -ForegroundColor red
                    write-Host "###########################################################################" -ForegroundColor Blue
                    write-Host ""
                }
        }
        }elseif ($Inspector -in $ANS_NO) {
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "         You have selected not to Proceed with Inspector !" -ForegroundColor yellow
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        } else {
            write-Host ""
            write-Host "###########################################################################" -ForegroundColor Blue
            Write-Host "                   Invalid choice " -ForegroundColor red
            write-Host "###########################################################################" -ForegroundColor Blue
            write-Host ""
        }
        
    }while (([String]::IsNullOrEmpty($Inspector ) -or [String]::IsNullOrWhiteSpace(($Inspector))))
}

function Cognito_fun {
    do {
        $ANS_YES = "y","yes","Yes","YES","Y","yES","yeS","YeS","yEs","YEs","yEs","YeS","yES","yEs","YES","yES","YeS"
        $ANS_NO = "n","no","No","NO","N","nO","nO","No","nO","NO","nO"
        write-Host ""
        $cognito_Service = Read-Host "Do you want to Proceed with Cognito Service ? (Y) | (N)"
        write-Host "---------------------------------------------------------------------"
        write-Host ""
        write-Host "================================================="
        write-Host "Checking Security On Current Users/Identity Pool"
        write-Host "================================================="
        if ($cognito_Service -in $ANS_YES){
            # Get Identity Pool
            $IdentityPool  = @()
            $IdentityPool = Get-CGIIdentityPoolList
            $n = 1
            $All_IdentityPool = foreach ($Identity in $IdentityPool) {
                write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                Write-Host " || Identity Pool Name-$($n): $($Identity.IdentityPoolName) || Identity Pool ID : $($Identity.IdentityPoolId) || " -ForegroundColor yellow 
                write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                $n++
            }
            $UserPool = @()
            $UserPool = Get-CGIPUserPoolList 
            $x = 1
            $All_UserPool = foreach ($User in $UserPool) {
                $Check_MFA_status = Get-CGIPUserPool  -UserPoolId $User.Id | select-object -ExpandProperty MfaConfiguration 
                if ($Check_MFA_status -eq "OPTIONAL") {
                    $Check_MFA_optional = "OPTIONAL" 
                }elseif($Check_MFA_status -eq "OFF"){
                    $Check_MFA = "OFF"
                }
                write-Host ""
                write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor blue
                Write-Host " || User Pool Name-$($x): $($User.Name)   || User Pool ID : $($User.Id)   || MFA : $Check_MFA_status   ||" 
                write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor blue
                
                
                $x++
            }
            write-Host ""
            $MFA_ON = Read-Host "Do you want to enable MFA for the User Pool '"'OFF Case'"'? (Y) | (N) "
            write-Host "---------------------------------------------------------------------"
            write-Host ""
            if ($MFA_ON -in $ANS_YES) {
                if($Check_MFA -eq "OFF"){
                    $UserPool = @()
                    $UserPool = Get-CGIPUserPoolList 
                    $x = 1
                    $All_UserPool = foreach ($User in $UserPool) {
                    $Check_MFA = Get-CGIPUserPool  -UserPoolId $User.Id | Where-Object {$_.MfaConfiguration -eq "OFF" } |select-object -ExpandProperty MfaConfiguration 
                        if ($Check_MFA -ne $null) {
                            write-Host ""
                            write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                            Write-Host " || User Pool Name-$($x): $($User.Name) || User Pool ID : $($User.Id) || MFA : $Check_MFA ||" 
                            write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                            write-Host ""
                            $x++
                        }else{
                            continue
                        }
                    }
                    if ($MFA_ON -in $ANS_YES) {
                        write-Host ""
                        $Selected_PoolIDs = Read-Host "Enter the User Pool ID(s) to Enable MFA, separated by commas"
                        write-Host "---------------------------------------------------------------------"
                        write-Host ""
                        $UserPoolIds = $Selected_PoolIDs -split "," | ForEach-Object { $_.Trim() }
                        foreach ($UserPoolId in $UserPoolIds) {
                        $MfaConfig = @{
                            MfaConfiguration = "ON"
                            SoftwareTokenMfaConfiguration = @{
                                Enabled = $true
                            }
                        }
                        $MFA_Operation = Set-CGIPUserPoolMfaConfig -UserPoolId $UserPoolId -MfaConfiguration $MfaConfig.MfaConfiguration -SoftwareTokenMfaConfiguration $MfaConfig.SoftwareTokenMfaConfiguration
                        write-Host "================================================" -foregroundcolor Magenta
                        write-Host "MFA Enabled Successfully For $UserPoolId " -ForegroundColor green
                        write-Host "================================================" -foregroundcolor Magenta
                    }
                    }elseif ($MFA_ON -in $ANS_NO) {
                        write-Host ""
                        Write-Host "You have selected not to Proceed with MFA Configuration !" -ForegroundColor yellow
                        write-Host "================================================" -foregroundcolor Magenta
                    } else {
                        write-Host ""
                        Write-Host "Invalid choice " -ForegroundColor red
                        write-Host "==============================" -foregroundcolor Magenta
                    }
                }else {
                    write-Host ""
                    Write-Host "There is no User Pool with MFA Configuration '"' OFF Case'"' !" -ForegroundColor yellow
                }
            }elseif($MFA_ON -in $ANS_NO){
                write-Host ""
                Write-Host "You have selected not to Proceed with MFA Configuration '"' OFF Case'"' !" -ForegroundColor yellow
            } else {
                write-Host ""
                Write-Host "Invalid choice " -ForegroundColor red
            }
            write-Host ""
            $MFA_Optional_ON = Read-Host "Do you want to Edit MFA Configuration for the User Pool '"' Optional Case'"' ? (Y) | (N) "
            write-Host "-------------------------------------------------------------------------"
            write-Host ""
            if($MFA_Optional_ON -in $ANS_YES){
                if ($Check_MFA_optional -eq "OPTIONAL") {
                    $UserPool_opt = @()
                    $UserPool_opt = Get-CGIPUserPoolList 
                    $c= 1
                    $All_UserPool = foreach ($User in $UserPool_opt) {
                    $Check_MFA_optional_on_inside = Get-CGIPUserPool  -UserPoolId $User.Id | Where-Object {$_.MfaConfiguration -eq "OPTIONAL" } |select-object -ExpandProperty MfaConfiguration 
                        if ($Check_MFA_optional_on_inside -ne $null) {
                            write-Host ""
                            write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                            Write-Host " || User Pool Name-$($c): $($User.Name) || User Pool ID : $($User.Id) || MFA : $Check_MFA_optional_on_inside ||" 
                            write-Host "------------------------------------------------------------------------------------------------------------" -foregroundcolor Magenta
                            $c++
                        }else{
                            continue
                        }
                    }   
                    if ($MFA_Optional_ON -in $ANS_YES) {
                        $Selected_PoolIDs_Optional = Read-Host "Enter the User Pool ID(s) to Enable MFA, separated by commas"
                        write-Host "---------------------------------------------------------------------"
                        write-Host ""
                        $UserPoolIds_Optional = $Selected_PoolIDs_Optional -split "," | ForEach-Object { $_.Trim() }
                        foreach ($UserPoolId_optional in $UserPoolIds_Optional) {
                        $MfaConfig_optional = @{
                            MfaConfiguration = "ON"
                            SoftwareTokenMfaConfiguration = @{
                                Enabled = $true
                            }
                        }
                        $MFA_Operation_optional = Set-CGIPUserPoolMfaConfig -UserPoolId $UserPoolId_optional -MfaConfiguration $MfaConfig_optional.MfaConfiguration -SoftwareTokenMfaConfiguration $MfaConfig_optional.SoftwareTokenMfaConfiguration
                        write-Host "================================================" -foregroundcolor Magenta
                        write-Host "MFA Enabled Successfully For $UserPoolId_optional " -ForegroundColor green
                        write-Host "================================================" -foregroundcolor Magenta
                    }
                    }elseif ($MFA_Optional_ON -in $ANS_NO) {
                        write-Host ""
                        Write-Host "You have selected not to Proceed with MFA Configuration !" -ForegroundColor yellow
                        write-Host "================================================" -foregroundcolor Magenta
                    } else {
                        write-Host ""
                        Write-Host "Invalid choice " -ForegroundColor red
                        write-Host "==============================" -foregroundcolor Magenta
                    }
                }else{
                    write-Host ""
                    Write-Host "There is no User Pool with MFA Configuration '"' OPTIONAL Case'"' !" -ForegroundColor yellow
                }
            }elseif($MFA_Optional_ON -in $ANS_NO){
                write-Host ""
                Write-Host "You have selected not to Proceed with MFA Configuration '"' OPTIONAL Case '"' !" -ForegroundColor yellow
            } else {
                write-Host ""
                Write-Host "Invalid choice " -ForegroundColor red
            }
            
            
        }elseif ($cognito_Service -in $ANS_NO){
            Write-Host "You have selected not to Proceed with Cognito Service !" -ForegroundColor yellow
        }else{
            Write-Host "Invalid choice " -ForegroundColor red
        }
    
    }while(([String]::IsNullOrEmpty($cognito_Service ) -or [String]::IsNullOrWhiteSpace(($cognito_Service))))
}




function aws-clouwatch {
    ##*===============================================
    ##* AWS CloudWatch
    ##*===============================================
    
    ################################################################################################
    $Closer = "1"
    ################################################################################################
    
    ##*===============================================
    ##* CloudWatch metric for failed console logins
    ##*===============================================
    
    ##################################################################
    ##*                       START
    ##################################################################


    $agree = Read-Host "Do you want to configure CloudWatch metric for failed console logins? (Y|N)"
    Write-Host ""
    If ($agree -eq "y"){

    Write-Host "" -ForegroundColor Yellow
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "AWS Console authentication process is being" -ForegroundColor Green
    Write-Host "monitored using CloudWatch alarms." -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Please select either to create a new log group or use an existing one?" -ForegroundColor Green
    Write-Host ""
    $groupChoice = Read-Host "Please enter your choice N for New | E for Existing" 
    
    if ($groupChoice -eq "N") {
        do {
            Write-Host ""
            $groupname = Read-Host "Please enter log group name"
            Write-Host ""
    
            $existingGroups = Get-CWLLogGroup -Region $region
    
            $groupExists = $existingGroups | Where-Object { $_.LogGroupName -eq $groupname }
    
            if ($groupExists) {
                Write-Host ""
                Write-Host "The specified log group already exists" -ForegroundColor Red
                Write-Host ""
                Write-Host "Please enter a different name" -ForegroundColor Yellow
                Write-Host ""
                $groupname = Read-Host "Please enter log group name"
                Write-Host ""
            } else {
                Write-Host ""
                Write-Host "Creating new log group..." -ForegroundColor Green
                New-CWLLogGroup -LogGroupName $groupname -Region $region
                $groupExists = $false
            }
        } while ($groupExists)
    
    } elseif ($groupChoice -eq "E") {
        Write-Host ""
        Write-Host "Please select one of the following log groups" -ForegroundColor Green
        Write-Host ""
        $existingGroups = Get-CWLLogGroup -Region $region
        $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
        Write-Host ""
        $groupname = Read-Host "Log group"
    
        $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
    
        while ($checkGroup -eq $null) {
            Write-Host ""
            Write-Host "Invalid choice. Please select one of the following log groups" -ForegroundColor Red
            Write-Host ""
    
            $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
            Write-Host ""
            $groupname = Read-Host "Log group"
            Write-Host ""
    
            $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $groupname
        }
    
        Write-Host ""
        Write-Host "Using existing log group: $groupname" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Invalid choice." -ForegroundColor Red
        Write-Host ""
    } 
    
    Write-Host "=========================================================" -ForegroundColor  Green
    write-Host "ComparisonOperator: The arithmetic operation to use" -ForegroundColor Green
    Write-Host "when comparing the specified statistic and threshold." -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host ""
    
        Write-Host ""
        Write-Host "Select a comparison operator:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. GreaterThanOrEqualToThreshold" -ForegroundColor Green
        Write-Host ""
        Write-Host "2. GreaterThanThreshold"  -ForegroundColor Green
        Write-Host ""
        Write-Host "3. LessThanOrEqualToThreshold"  -ForegroundColor Green
        Write-Host ""
        Write-Host "4. LessThanThreshold"  -ForegroundColor Green
        Write-Host ""
        $comparisonOperatorChoice = Read-Host "Enter the selected comparison operator"
        Write-Host ""
    

        Write-Host ""
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host "Please define the SNS (Simple Notification Service) topic" -ForegroundColor Green
        Write-Host "that will receive the notification. Specify if you want to" -ForegroundColor Green
        Write-Host "use an existing SNS topic or create a new topic" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host ""
    
    $Topic_select = Read-Host "Please enter you choice: N for New SNS topic | E for Existing SNS topic"

        IF($topic_select -eq "N"){
            
            Write-Host""
            $snsTopicName = Read-Host "Please enter SNS topic name"
            write-Host ""
            $snsDisplayName = Read-Host "Please enter SNS Display Name" 
            Write-Host ""

            $topics = Get-SNSTopic -Region $region
                IF($topic.TopicArn.Split(':')[-1] -eq  $snsTopicName)  {                
                    Write-Host ""

                    Write-Host "SNS topic name already exists. Please enter a different SNS topic name" -ForegroundColor Red
                    Write-Host ""
                    $snsTopicName = Read-Host "Please enter SNS topic name"
                    Write-Host ""
    
                    $check_SNS =  Get-SNSTopic -Region $region 
                   
                }else{
                    Write-Host ""
                    Write-Host "Creating SNS Topic..." -ForegroundColor Green
                    $snsTopicArn = New-SNSTopic -Region $region -Name $snsTopicName
                    Write-Host""
                    Write-Host "Setting SNS Topic Display Name..." -ForegroundColor Green
                    Set-SNSTopicAttribute -TopicArn $snsTopic -AttributeName DisplayName -AttributeValue $snsDisplayName -Region $region
                    Write-Host ""
                    Write-Host New SNS topic was created successfully with topic Arn $($snsTopic) -ForegroundColor Yellow 

                    }
            
                write-Host ""
                Write-Host "Please specify Email endpoints that will receive the notification…" -ForegroundColor Green
                Write-Host "Enter the email addresses to subscribe (comma separated). Each address will be added as a subscription to the topic above." -ForegroundColor Green
                Write-Host""
                $emails = Read-Host "Enter e-mails" -Split ','
            
                    # Subscribe Emails to SNS Topicl

                    Write-Host ""
                    Write-Host "Please check your e-mail to confirm SNS subscription" -ForegroundColor Red
                    Write-Host ""
                    foreach ($email in $emails) {
                        $trimmedEmail = $email.Trim()
                        Write-Host "Subscribing email $trimmedEmail to SNS Topic..."
                        Connect-SNSNotification -Region $region -TopicArn $snsTopic -Protocol "email" -Endpoint $email
                    }
                        
            
            }elseif ($topic_select -eq "E") {

                $list =  Get-SNSTopic -Region $region
                
                Write-Host ""
                Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                Write-Host ""

                $list | ForEach-Object {

                    Write-Host ""
                    Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                    Write-Host ""
                    $validate = $list.TopicArn
                }

                $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
            
                       If ($validate -notcontains $SNS_selected){

                        Write-Host ""
                        write-Host "Invalid Choice" -ForegroundColor Red
                        Write-Host ""
                        $list =  Get-SNSTopic -Region $region
                
                        Write-Host ""
                        Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                        Write-Host ""
    
                        $list | ForEach-Object {
    
                            Write-Host ""
                            Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                            Write-Host ""
                            $validate = $list.TopicArn
                        }
    
                        $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                       }
                    }else {
                        Write-Host ""
                        Write-Host "Invalid choice" -ForegroundColor Red
                        Write-Host
                    }
  
    
    $alarmPrefix = "ConsoleAuthMonitoring"
    
    $metric = New-Object -TypeName Amazon.CloudWatchLogs.Model.MetricTransformation
    $metric.MetricNamespace = "AWS/Console"
    $metric.MetricName ="FailedLogins"
    $metric.MetricValue = 1
    
    $metricFilter = Write-CWLMetricFilter -Region $region -FilterName "ConsoleAuthMonitoring" -MetricTransformation $metric -FilterPattern "{ $.eventName = 'ConsoleLogin' && $.errorCode = 'AccessDenied' }" -LogGroupName $groupname
    
    # Create a CloudWatch alarm for failed console logins
    $alarm = Write-CWMetricAlarm -Region $region -AlarmName "$alarmPrefix-FailedLoginsAlarm" -MetricName "FailedLogins" -Namespace "AWS/Console" -Statistic "Sum" -Period 300 -EvaluationPeriods 1 -Threshold 1 -ComparisonOperator  $comparisonOperatorChoice -ActionsEnabled $true -AlarmAction $snsTopicArn
    
    Write-Host "CloudWatch alarms and SNS topic created for Console authentication monitoring" -ForegroundColor Green
    write-Host ""
    }  

 
    
    ##*==================================================
    ##* CloudWatch security groups configuration changes
    ##*==================================================

    $agree = Read-Host "DO you want to configure CloudWatch security groups configuration changes? (Y|N)"
    Write-Host ""
    
        Write-Host "Please select either to create a new log group or use an existing one?" -ForegroundColor Green
        Write-Host ""
        $groupChoice = Read-Host "Please enter your choice N for New | E for Existing" 
        
        if ($groupChoice -eq "N") {
            do {
                Write-Host ""
                $groupname = Read-Host "Please enter log group name"
                Write-Host ""
        
                $existingGroups = Get-CWLLogGroup -Region $region
        
                $groupExists = $existingGroups | Where-Object { $_.LogGroupName -eq $groupname }
        
                if ($groupExists) {
                    Write-Host ""
                    Write-Host "The specified log group already exists" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "Please enter a different name" -ForegroundColor Yellow
                } else {
                    Write-Host ""
                    Write-Host "Creating new log group..." -ForegroundColor Green
                    New-CWLLogGroup -LogGroupName $groupname -Region $region
                    $groupExists = $false
                }
            } while ($groupExists)
        
        } elseif ($groupChoice -eq "E") {
            Write-Host ""
            Write-Host "Please select one of the following log groups" -ForegroundColor Green
            Write-Host ""
            $existingGroups = Get-CWLLogGroup -Region $region
            $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
            Write-Host ""
            $logGroup = Read-Host "Log group"
        
            $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
        
            while ($checkGroup -eq $null) {
                Write-Host ""
                Write-Host "Invalid choice. Please select one of the following log groups" -ForegroundColor Red
                Write-Host ""
        
                $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
                Write-Host ""
                $logGroup = Read-Host "Log group"
                Write-Host ""
        
                $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
            }
        
            Write-Host ""
            Write-Host "Using existing log group: $logGroup" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "Invalid choice." -ForegroundColor Red
            Write-Host ""
        } 

        Write-Host "====================================================" -ForegroundColor  Green
        write-Host "ComparisonOperator: The arithmetic operation to use" -ForegroundColor Green
        Write-Host "when comparing the specified statistic and threshold." -ForegroundColor Green
        Write-Host "=====================================================" -ForegroundColor Green
        Write-Host ""
       
        
        Write-Host ""
        Write-Host "Select a comparison operator:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "1. GreaterThanOrEqualToThreshold" -ForegroundColor Green
        Write-Host ""
        Write-Host "2. GreaterThanThreshold"  -ForegroundColor Green
        Write-Host ""
        Write-Host "3. LessThanOrEqualToThreshold"  -ForegroundColor Green
        Write-Host ""
        Write-Host "4. LessThanThreshold"  -ForegroundColor Green
        Write-Host ""
        $comparisonOperatorChoice = Read-Host "Enter the selected comparison operator"
        Write-Host ""
    
    

        Write-Host ""
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host "Please define the SNS (Simple Notification Service) topic" -ForegroundColor Green
        Write-Host "that will receive the notification. Specify if you want to" -ForegroundColor Green
        Write-Host "use an existing SNS topic or create a new topic" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host ""
        $Topic_select = Read-Host "Please enter you choice: N for New SNS topic | E for Existing SNS topic"

            IF($topic_select -eq "N"){
                
                Write-Host""
                $snsTopicName = Read-Host "Please enter SNS topic name"
                write-Host ""
                $snsDisplayName = Read-Host "Please enter SNS Display Name" 
                Write-Host ""

                $topics = Get-SNSTopic -Region $region
                    IF($topic.TopicArn.Split(':')[-1] -eq  $snsTopicName)  {                
                        Write-Host ""

                        Write-Host "SNS topic name already exists. Please enter a different SNS topic name" -ForegroundColor Red
                        Write-Host ""
                        $snsTopicName = Read-Host "Please enter SNS topic name"
                        Write-Host ""
        
                        $check_SNS =  Get-SNSTopic -Region $region 
                       
                    }else{
                        Write-Host ""
                        Write-Host "Creating SNS Topic..." -ForegroundColor Green
                        $snsTopicArn = New-SNSTopic -Region $region -Name $snsTopicName
                        Write-Host""
                        Write-Host "Setting SNS Topic Display Name..." -ForegroundColor Green
                        Set-SNSTopicAttribute -TopicArn $snsTopic -AttributeName DisplayName -AttributeValue $snsDisplayName -Region $region
                        Write-Host ""
                        Write-Host New SNS topic was created successfully with topic Arn $($snsTopic) -ForegroundColor Yellow 
 
                        }
                
                    write-Host ""
                    Write-Host "Please specify Email endpoints that will receive the notification…" -ForegroundColor Green
                    Write-Host "Enter the email addresses to subscribe (comma separated). Each address will be added as a subscription to the topic above." -ForegroundColor Green
                    Write-Host""
                    $emails = Read-Host "Enter e-mails" -Split ','
                
                        # Subscribe Emails to SNS Topicl
    
                        Write-Host ""
                        Write-Host "Please check your e-mail to confirm SNS subscription" -ForegroundColor Red
                        Write-Host ""
                        foreach ($email in $emails) {
                            $trimmedEmail = $email.Trim()
                            Write-Host "Subscribing email $trimmedEmail to SNS Topic..."
                            Connect-SNSNotification -Region $region -TopicArn $snsTopic -Protocol "email" -Endpoint $email
                        }
                            
                
                }elseif ($topic_select -eq "E") {

                    $list =  Get-SNSTopic -Region $region
                    
                    Write-Host ""
                    Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                    Write-Host ""

                    $list | ForEach-Object {

                        Write-Host ""
                        Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                        Write-Host ""
                        $validate = $list.TopicArn
                    }

                    $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                
                           If ($validate -notcontains $SNS_selected){

                            Write-Host ""
                            write-Host "Invalid Choice" -ForegroundColor Red
                            Write-Host ""
                            $list =  Get-SNSTopic -Region $region
                    
                            Write-Host ""
                            Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                            Write-Host ""
        
                            $list | ForEach-Object {
        
                                Write-Host ""
                                Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                                Write-Host ""
                                $validate = $list.TopicArn
                            }
        
                            $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                           }
                        }else {
                            Write-Host ""
                            Write-Host "Invalid choice" -ForegroundColor Red
                            Write-Host
                        }     
    
     
     
    
    $logStreamName = "SecurityGroupChangesStream"
    New-CWLLogStream -Region $region -LogGroupName  $groupname  -LogStreamName $logStreamName
    
    # Create a CloudWatch metric filter for Security Group changes
    
    $metric = New-Object -TypeName Amazon.CloudWatchLogs.Model.MetricTransformation
    $metric.MetricNamespace = "Security/Config"
    $metric.MetricName = "ConfigChanges"
    $metric.MetricValue = 1
    
    
    $metricFilterName = "SecurityGroupChangesFilter"
    $metricFilterPattern = '{ $.eventName = "AuthorizeSecurityGroupIngress" || $.eventName = "AuthorizeSecurityGroupEgress" || $.eventName = "RevokeSecurityGroupIngress" || $.eventName = "RevokeSecurityGroupEgress" || $.eventName = "CreateSecurityGroup" || $.eventName = "DeleteSecurityGroup" }'
    Write-CWLMetricFilter -Region $region -LogGroupName  $groupname  -FilterName $metricFilterName -FilterPattern $metricFilterPattern -MetricTransformation $metric 
    
    # Create a CloudWatch alarm for Security Group changes
    $alarmName = "SecurityGroupChangesAlarm"
    $alarmDescription = "Alarm for Security Group changes"
    $threshold = 1
    $evaluationPeriods = 1
    $period = 300
    $statistic = "Sum"
    $unit = "Count"
    
    $alarm = Write-CWMetricAlarm -Region $region -AlarmName $alarmName -AlarmDescription $alarmDescription -MetricName $metricFilterName -Namespace "AWS/CloudWatch" -Statistic $statistic -Period $period -EvaluationPeriods $evaluationPeriods -Threshold $threshold -ComparisonOperator $comparisonOperatorChoice -Unit $unit -ActionsEnabled $true -AlarmAction $snsTopicArn
    
    Write-Host "CloudWatch log group, log stream, metric filter, alarm, and SNS topic created for Security Group changes monitoring" -ForegroundColor Yellow
    Write-Host ""
    
    
    Write-Host "===============================================================================" -ForegroundColor Blue
    Write-Host "===============================================================================" -ForegroundColor Blue
    Write-Host ""
    ##*==================================================
    ##* CloudWatch EC2 StatusCheckFailed
    ##*==================================================
    
    $ec2alarm = Read-Host "Please enter Y if you want to create alarm for ec2 status check failed"
    
    IF ($ec2alarm -eq "Y"){

       
            Write-Host "Please select either to create a new log group or use an existing one?" -ForegroundColor Green
            Write-Host ""
            $groupChoice = Read-Host "Please enter your choice N for New | E for Existing" 
            
            if ($groupChoice -eq "N") {
                do {
                    Write-Host ""
                    $groupname = Read-Host "Please enter log group name"
                    Write-Host ""
            
                    $existingGroups = Get-CWLLogGroup -Region $region
            
                    $groupExists = $existingGroups | Where-Object { $_.LogGroupName -eq $groupname }
            
                    if ($groupExists) {
                        Write-Host ""
                        Write-Host "The specified log group already exists" -ForegroundColor Red
                        Write-Host ""
                        Write-Host "Please enter a different name" -ForegroundColor Yellow
                    } else {
                        Write-Host ""
                        Write-Host "Creating new log group..." -ForegroundColor Green
                        New-CWLLogGroup -LogGroupName $groupname -Region $region
                        $groupExists = $false
                    }
                } while ($groupExists)
            
            } elseif ($groupChoice -eq "E") {
                Write-Host ""
                Write-Host "Please select one of the following log groups" -ForegroundColor Green
                Write-Host ""
                $existingGroups = Get-CWLLogGroup -Region $region
                $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
                Write-Host ""
                $logGroup = Read-Host "Log group"
            
                $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
            
                while ($checkGroup -eq $null) {
                    Write-Host ""
                    Write-Host "Invalid choice. Please select one of the following log groups" -ForegroundColor Red
                    Write-Host ""
            
                    $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
                    Write-Host ""
                    $logGroup = Read-Host "Log group"
                    Write-Host ""
            
                    $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
                }
            
                Write-Host ""
                Write-Host "Using existing log group: $logGroup" -ForegroundColor Green
            } else {
                Write-Host ""
                Write-Host "Invalid choice." -ForegroundColor Red
                Write-Host ""
            } 
       
            
        Write-Host "Please select one of the following EC2 instances" -ForegroundColor Yellow
            Write-Host ""

            $instances = Get-EC2Instance -Region $region
            $instances.Instances | ForEach-Object {
                $instanceId = $_.InstanceId
                $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                write-host "-------------------------------------" -ForegroundColor Blue
                Write-host "Instance Name: $nameTag "   -ForegroundColor Green
                Write-host "Instance ID: $instanceId" -ForegroundColor Green
                write-host "-------------------------------------" -ForegroundColor Blue
            }

            Write-Host ""
            $select = Read-Host "Please enter instance id of the instance you want"
            Write-Host ""

            $check_instances = (Get-EC2Instance -Region $region).Instances.InstanceId

            while ($check_instances -notcontains $select) {
                Write-Host ""
                Write-Host "Invalid EC2 instance id. Please select one of the following EC2 instances " -ForegroundColor Red
                Write-Host ""
                $instances.Instances | ForEach-Object {
                    $instanceId = $_.InstanceId
                    $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                    write-host "-------------------------------------" -ForegroundColor Blue
                    Write-host "Instance Name: $nameTag "   -ForegroundColor Green
                    Write-host "Instance ID: $instanceId" -ForegroundColor Green
                    write-host "-------------------------------------" -ForegroundColor Blue
                }
                Write-Host ""
                $select = Read-Host "Please enter instance id of the instance you want"
                Write-Host ""
            }
        
            Write-Host "====================================================" -ForegroundColor  Green
            write-Host "ComparisonOperator: The arithmetic operation to use" -ForegroundColor Green
            Write-Host "when comparing the specified statistic and threshold." -ForegroundColor Green
            Write-Host "=====================================================" -ForegroundColor Green
            Write-Host ""
    
                Write-Host ""
                Write-Host "Select a comparison operator:" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "1. GreaterThanOrEqualToThreshold" -ForegroundColor Green
                Write-Host ""
                Write-Host "2. GreaterThanThreshold"  -ForegroundColor Green
                Write-Host ""
                Write-Host "3. LessThanOrEqualToThreshold"  -ForegroundColor Green
                Write-Host ""
                Write-Host "4. LessThanThreshold"  -ForegroundColor Green
                Write-Host ""
                $comparisonOperatorChoice = Read-Host "Enter the selected comparison operator"
                Write-Host ""
            
        
        $alarmName = "EC2StatusCheckFailedAlarm"
        $threshold = 1  
        $evaluationPeriods = 1
        $period = 300 

  
        Write-Host ""
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host "Please define the SNS (Simple Notification Service) topic" -ForegroundColor Green
        Write-Host "that will receive the notification. Specify if you want to" -ForegroundColor Green
        Write-Host "use an existing SNS topic or create a new topic" -ForegroundColor Green
        Write-Host "========================================================================" -ForegroundColor Green
        Write-Host ""
        $Topic_select = Read-Host "Please enter you choice: N for New SNS topic | E for Existing SNS topic"

            IF($topic_select -eq "N"){
                
                Write-Host""
                $snsTopicName = Read-Host "Please enter SNS topic name"
                write-Host ""
                $snsDisplayName = Read-Host "Please enter SNS Display Name" 
                Write-Host ""

                $topics = Get-SNSTopic -Region $region
                    IF($topic.TopicArn.Split(':')[-1] -eq  $snsTopicName)  {                
                        Write-Host ""

                        Write-Host "SNS topic name already exists. Please enter a different SNS topic name" -ForegroundColor Red
                        Write-Host ""
                        $snsTopicName = Read-Host "Please enter SNS topic name"
                        Write-Host ""
        
                        $check_SNS =  Get-SNSTopic -Region $region 
                       
                    }else{
                        Write-Host ""
                        Write-Host "Creating SNS Topic..." -ForegroundColor Green
                        $snsTopicArn = New-SNSTopic -Region $region -Name $snsTopicName
                        Write-Host""
                        Write-Host "Setting SNS Topic Display Name..." -ForegroundColor Green
                        Set-SNSTopicAttribute -TopicArn $snsTopic -AttributeName DisplayName -AttributeValue $snsDisplayName -Region $region
                        Write-Host ""
                        Write-Host New SNS topic was created successfully with topic Arn $($snsTopic) -ForegroundColor Yellow 
 
                        }
                
                    write-Host ""
                    Write-Host "Please specify Email endpoints that will receive the notification…" -ForegroundColor Green
                    Write-Host "Enter the email addresses to subscribe (comma separated). Each address will be added as a subscription to the topic above." -ForegroundColor Green
                    Write-Host""
                    $emails = Read-Host "Enter e-mails" -Split ','
                
                        # Subscribe Emails to SNS Topicl
    
                        Write-Host ""
                        Write-Host "Please check your e-mail to confirm SNS subscription" -ForegroundColor Red
                        Write-Host ""
                        foreach ($email in $emails) {
                            $trimmedEmail = $email.Trim()
                            Write-Host "Subscribing email $trimmedEmail to SNS Topic..."
                            Connect-SNSNotification -Region $region -TopicArn $snsTopic -Protocol "email" -Endpoint $email
                        }
                            
                
                }elseif ($topic_select -eq "E") {

                    $list =  Get-SNSTopic -Region $region
                    
                    Write-Host ""
                    Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                    Write-Host ""

                    $list | ForEach-Object {

                        Write-Host ""
                        Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                        Write-Host ""
                        $validate = $list.TopicArn
                    }

                    $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                
                           If ($validate -notcontains $SNS_selected){

                            Write-Host ""
                            write-Host "Invalid Choice" -ForegroundColor Red
                            Write-Host ""
                            $list =  Get-SNSTopic -Region $region
                    
                            Write-Host ""
                            Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                            Write-Host ""
        
                            $list | ForEach-Object {
        
                                Write-Host ""
                                Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                                Write-Host ""
                                $validate = $list.TopicArn
                            }
        
                            $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                           }
                        }else {
                            Write-Host ""
                            Write-Host "Invalid choice" -ForegroundColor Red
                            Write-Host
                        }
           
                
    
        # Create CloudWatch Alarm
        Write-Output "Creating CloudWatch Alarm for EC2 StatusCheckFailed..."
        Write-CWMetricAlarm -AlarmName $alarmName `
                        -MetricName "StatusCheckFailed" `
                        -Namespace "AWS/EC2" `
                        -Statistic "Maximum" `
                        -Dimensions @{"Name"="InstanceId";"Value"=$instanceId} `
                        -Period $period `
                        -EvaluationPeriods $evaluationPeriods `
                        -Threshold $threshold `
                        -ComparisonOperator  $comparisonOperatorChoice `
                        -AlarmActions  $snsTopicArn `
                        -Region $region
    
        Write-Host "CloudWatch Alarm for EC2 StatusCheckFailed has been created successfully." -ForegroundColor Green
        Write-Host ""
    
    }

    
    ##*==================================================
    ##* CloudWatch EC2 CPU utilization
    ##*==================================================
    Write-Host ""
    $ec2_cpu_alarm = Read-Host "Do you want to create alarm for EC2 CPU utilization? (Y|N)"
    $region = "us-east-1"
        If($ec2_cpu_alarm  -eq "y"){

            Write-Host ""
            $alarmName = Read-Host "Please enter alarm name"
            Write-Host ""
            
                Write-Host "Please select either to create a new log group or use an existing one?" -ForegroundColor Green
                Write-Host ""
                $groupChoice = Read-Host "Please enter your choice N for New | E for Existing" 
                
                if ($groupChoice -eq "N") {
                    do {
                        Write-Host ""
                        $groupname = Read-Host "Please enter log group name"
                        Write-Host ""
                
                        $existingGroups = Get-CWLLogGroup -Region $region
                
                        $groupExists = $existingGroups | Where-Object { $_.LogGroupName -eq $groupname }
                
                        if ($groupExists) {
                            Write-Host ""
                            Write-Host "The specified log group already exists" -ForegroundColor Red
                            Write-Host ""
                            Write-Host "Please enter a different name" -ForegroundColor Yellow
                        } else {
                            Write-Host ""
                            Write-Host "Creating new log group..." -ForegroundColor Green
                            New-CWLLogGroup -LogGroupName $groupname -Region $region
                            $groupExists = $false
                        }
                    } while ($groupExists)
                
                } elseif ($groupChoice -eq "E") {
                    Write-Host ""
                    Write-Host "Please select one of the following log groups" -ForegroundColor Green
                    Write-Host ""
                    $existingGroups = Get-CWLLogGroup -Region $region
                    $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
                    Write-Host ""
                    $logGroup = Read-Host "Log group"
                
                    $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
                
                    while ($checkGroup -eq $null) {
                        Write-Host ""
                        Write-Host "Invalid choice. Please select one of the following log groups" -ForegroundColor Red
                        Write-Host ""
                
                        $existingGroups | ForEach-Object { Write-Host $_.LogGroupName -ForegroundColor Yellow }
                        Write-Host ""
                        $logGroup = Read-Host "Log group"
                        Write-Host ""
                
                        $checkGroup = Get-CWLLogGroup -Region $region -LogGroupNamePattern $logGroup
                    }
                
                    Write-Host ""
                    Write-Host "Using existing log group: $logGroup" -ForegroundColor Green
                } else {
                    Write-Host ""
                    Write-Host "Invalid choice." -ForegroundColor Red
                    Write-Host ""
                } 
                

                Write-Host "Please select one of the following EC2 instances" -ForegroundColor Yellow
                Write-Host ""

                $instances = Get-EC2Instance -Region $region
                $instances.Instances | ForEach-Object {
                    $instanceId = $_.InstanceId
                    $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                    write-host "-------------------------------------" -ForegroundColor Blue
                    Write-host "Instance Name: $nameTag "   -ForegroundColor Green
                    Write-host "Instance ID: $instanceId" -ForegroundColor Green
                    write-host "-------------------------------------" -ForegroundColor Blue
                }

                Write-Host ""
                $select = Read-Host "Please enter instance id of the instance you want"
                Write-Host ""

                $check_instances = (Get-EC2Instance -Region $region).Instances.InstanceId

                while ($check_instances -notcontains $select) {
                    Write-Host ""
                    Write-Host "Invalid EC2 instance id. Please select one of the following EC2 instances " -ForegroundColor Red
                    Write-Host ""
                    $instances.Instances | ForEach-Object {
                        $instanceId = $_.InstanceId
                        $nameTag = $_.Tags | Where-Object { $_.Key -eq "Name" } | Select-Object -ExpandProperty Value
                        write-host "-------------------------------------" -ForegroundColor Blue
                        Write-host "Instance Name: $nameTag "   -ForegroundColor Green
                        Write-host "Instance ID: $instanceId" -ForegroundColor Green
                        write-host "-------------------------------------" -ForegroundColor Blue
                    }
                    Write-Host ""
                    $select = Read-Host "Please enter instance id of the instance you want"
                    Write-Host ""
                }
                            
            Write-Host "========================================================================================================" -ForegroundColor  Green
            write-Host "Period: The length, in seconds, used each time the metric specified in MetricName is evaluated. Valid " -ForegroundColor Green
            write-Host "values are 10, 30, and any multiple of 60.Period is required for alarms based on static thresholds." -ForegroundColor Green
            Write-Host "========================================================================================================" -ForegroundColor Green
            Write-Host ""
            
            $period = Read-Host Please enter the desired period in seconds

            Write-Host "====================================================" -ForegroundColor  Green
            write-Host "ComparisonOperator: The arithmetic operation to use" -ForegroundColor Green
            Write-Host "when comparing the specified statistic and threshold." -ForegroundColor Green
            Write-Host "=====================================================" -ForegroundColor Green
            Write-Host ""

        
            
                Write-Host ""
                Write-Host "Select a comparison operator:" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "1. GreaterThanOrEqualToThreshold" -ForegroundColor Green
                Write-Host ""
                Write-Host "2. GreaterThanThreshold"  -ForegroundColor Green
                Write-Host ""
                Write-Host "3. LessThanOrEqualToThreshold"  -ForegroundColor Green
                Write-Host ""
                Write-Host "4. LessThanThreshold"  -ForegroundColor Green
                Write-Host ""
                $comparisonOperatorChoice = Read-Host "Enter the selected comparison operator"
                Write-Host ""
            
            # $alarm_condition = New-Object -TypeName Amazon.CloudWatch.Model.comp
            Write-Host ""
            Write-Host "Threshold which is the value against which the specified statistic is compared" -ForegroundColor Green
            Write-Host
            Write-Host "Alarm threshold for CPU utilization in percentage, Ex: 80"
            Write-Host ""
            $threshold = Read-Host Please enter the threshold you want

            Write-Host ""
            Write-Host "========================================================================" -ForegroundColor Green
            Write-Host "Please define the SNS (Simple Notification Service) topic" -ForegroundColor Green
            Write-Host "that will receive the notification. Specify if you want to" -ForegroundColor Green
            Write-Host "use an existing SNS topic or create a new topic" -ForegroundColor Green
            Write-Host "========================================================================" -ForegroundColor Green
            Write-Host ""
            
            $Topic_select = Read-Host "Please enter you choice: N for New SNS topic | E for Existing SNS topic"

                IF($topic_select -eq "N"){
                    
                    Write-Host ""
                    $snsTopicName = Read-Host "Please enter SNS Topic Name"
                    write-Host ""
                    $snsDisplayName = Read-Host "Please enter SNS Display Name" 
                    Write-Host ""

                    $topics = Get-SNSTopic -Region $region
                        IF($topic.TopicArn.Split(':')[-1] -eq $snsTopicName)  {                
                            Write-Host ""

                            Write-Host "SNS topic name already exists. Please enter a different SNS topic name" -ForegroundColor Red
                            Write-Host ""
                        $snsTopicName = Read-Host "Please enter SNS Topic Name"
                            Write-Host ""
            
                            $check_SNS =  Get-SNSTopic -Region $region 
                        
                        }else{
                            Write-Host ""
                            Write-Host "Setting SNS Topic Display Name..." -ForegroundColor Green

                            $snsTopic = New-SNSTopic -Region $region -Name $snsTopicName 
        
                            Write-Host ""
                            Write-Host New SNS topic was created successfully with topic Arn $($snsTopic) -ForegroundColor Yellow 
    
                            }
                    
                        write-Host ""
                        Write-Host "Please specify Email endpoints that will receive the notification…" -ForegroundColor Green
                        Write-Host "Enter the email addresses to subscribe (comma separated). Each address will be added as a subscription to the topic above." -ForegroundColor Green
                        Write-Host""
                        $emails = Read-Host "Enter e-mails" -Split ','
                    
                            # Subscribe Emails to SNS Topicl
        
                            Write-Host ""
                            Write-Host "Please check your e-mail to confirm SNS subscription" -ForegroundColor Red
                            Write-Host ""
                            foreach ($email in $emails) {
                                $trimmedEmail = $email.Trim()
                                Write-Host "Subscribing email $trimmedEmail to SNS Topic..."
                                Connect-SNSNotification -Region $region -TopicArn $snsTopic -Protocol "email" -Endpoint $email
                            }
                                
                    
                    }elseif ($topic_select -eq "E") {

                        $list =  Get-SNSTopic -Region $region
                        
                        Write-Host ""
                        Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                        Write-Host ""

                        $list | ForEach-Object {

                            Write-Host ""
                            Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                            Write-Host ""
                            $validate = $list.TopicArn
                        }

                        $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                    
                            If ($validate -notcontains $SNS_selected){

                                Write-Host ""
                                write-Host "Invalid Choice" -ForegroundColor Red
                                Write-Host ""
                                $list =  Get-SNSTopic -Region $region
                        
                                Write-Host ""
                                Write-Host "Please select one of the following SNS topics" -ForegroundColor Green
                                Write-Host ""
            
                                $list | ForEach-Object {
            
                                    Write-Host ""
                                    Write-Host TopicArn: $_.TopicArn -ForegroundColor Yellow
                                    Write-Host ""
                                    $validate = $list.TopicArn
                                }
            
                                $snsTopicArn = Read-Host "Please enter the selected Topic Arn"
                            }
                            }else {
                                Write-Host ""
                                Write-Host "Invalid choice" -ForegroundColor Red
                                Write-Host
                            }
            
                    
                
                ## Create CloudWatch Alarm
                Write-CWMetricAlarm -Region $region -AlarmName $alarmName -MetricName "CPUUtilization" -Namespace "AWS/EC2" -Statistic "Average" -Period $period -EvaluationPeriods 1 -Threshold $threshold -ComparisonOperator "GreaterThanThreshold" -ActionsEnabled $true  -Dimensions @{"Name"="InstanceId";"Value"=$instanceId} -AlarmAction  $snsTopicArn

                Write-Host ""
                Write-host "CloudWatch Alarm for EC2 CPU Utilization has been created successfully." -ForegroundColor Green

        }
                ##################################################################
                ##*                            END
                ##################################################################
            
                Write-Host ""
                Write-Host "===============================================" -ForegroundColor Green
                Write-Host "Creating CloudWatch Alarms has been Completed" -ForegroundColor Green
                Write-Host "===============================================" -ForegroundColor Green
        


}

function aws_artifact {


##*===============================================
##* AWS Artifact
##*===============================================

################################################################################################
$Closer = "1"
################################################################################################


##*===============================================
##* AWS Artifact Reports
##*===============================================
Write-Host ""
$artifact = Read-Host "Please enter Y if you want to configure AWS Artifact Reports"

IF($artifact -eq "Y"){

Write-Host "" -ForegroundColor Yellow
Write-Host "===================================================================="-ForegroundColor Green
Write-Host "AWS Artifact is your go-to, central resource for" -ForegroundColor Green
Write-Host "compliance-related information that matters to you."
Write-Host "It provides on-demand access to security and compliance "  -ForegroundColor Green
Write-Host "reports from AWS and ISVs who sell their products on AWS Marketplace." -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""

$reports = Get-ARTReportList -Region $region

# Display the list of reports
Write-Host "Reports for the current account or organization:" -ForegroundColor Yellow
$reports | ForEach-Object { Write-Host Report Name: $_.Name , "|" ReportId: $_.Id , "|" Repoert Version: $_.Version }
Write-Host""
Write-Host "Do you want to download a report? (y/n)" -ForegroundColor Yellow
Write-Host""
$response = Read-Host "Enter your choice"

if ($response -eq "y") {
    Write-Host ""
    Write-Host "Enter the report ID:" -ForegroundColor Yellow
    Write-Host""
    $reportId = Read-Host "Report ID"
    
    $token = Get-ARTTermForReport -Region $region -ReportId $reportId
    Write-Host ""
    write-host Your report term token is: $token.TermToken -ForegroundColor DarkMagenta

    # Download the report
    $report = Get-ARTReport -Region $region -ReportId $reportId -TermToken $token.TermToken

    Write-Host Your report link is ready $report
    Write-Host""
    Write-Host copy and paste the link to download the report -ForegroundColor Yellow
} else {
    Write-Host "No report downloaded."
}


##*===============================================
##* AWS Artifact Notifications
##*===============================================

Write-Host "" -ForegroundColor Yellow
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "You can Subscribe to Artifact notifications and create"
Write-Host "custom configurations to receive agreement and report updates."  -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Do you want to Subscribe to Artifact notifications? (y/n)" -ForegroundColor Yellow
$agree = Read-Host "Enter your choice"

    IF($agree -eq "y"){
        
        Write-ARTAccountSetting -Region $region -NotificationSubscriptionStatus SUBSCRIBED 

        Write-Host Subscription to AWS Artifact notifications is done -ForegroundColor DarkMagenta

        Write-Host ""
        write-Host "Please enter your email address that will be used"
        $email = Read-Host "Your E-mail"


    }

    $reports = Get-ARTReportList -Region $region

    foreach ($report in $reports) {
        if ($report.StatusMessage -eq "UPDATED") {
            
            Write-Host "Report $($report.Name) has been updated."

            Set-SESIdentityNotificationTopic -Identity $email -NotificationType Delivery -SnsTopic "AWS Artifact Report updates"
            
        }
    }

        ##################################################################
        ##*                            END
        ##################################################################
    
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Green
        Write-Host "Configuring AWS Artifact has been Completed" -ForegroundColor Green
        Write-Host "===============================================" -ForegroundColor Green
}

}
function awsresources_mountring {


        
    ##*===============================================
    ##* EC2 Monitoring
    ##*===============================================
    Write-Host ""
    $Ec2 = Read-Host "Do you want to configure EC2 Monitoring? (Y|N)"
    write-Host ""

    IF($Ec2 -eq "Y"){
    
    $instec2instances = (Get-EC2Instance -Region $region).Instances | Select-Object InstanceId
    IF($instec2instances -eq $null){

        Write-Host ""
        Write-Host "There are no any instances in the specified region: $($region)" -ForegroundColor Red
        Write-Host ""
    }else{

    $count = $instec2instances.Count
    
    Write-Host You have $($count) instances with instance IDs $($instec2instances) exist ...   -ForegroundColor Green 
    Write-Host ""     
    
    $get = (Get-EC2Instance -Region $region -Filter @( @{ Name = "instance-state-name"; Values = "running" } , @{ Name = "monitoring-state"; Values = "enabled" })).Instances | Select-Object InstanceId
    
    IF ($get -eq $null){

        Write-Host ""
        Write-Host "No EC2 instances have monitoring enabled" -ForegroundColor Red
        Write-Host ""
    }
    else {

        Write-Host $($get.Count) instances with IDs $($get) have monitoring enabled -ForegroundColor Green
        Write-Host ""
    }
    
    $get_01 = (Get-EC2Instance -Region $region -Filter @{Name="monitoring-state" ; Values="disabled"}).Instances | Select-Object InstanceId
    
    IF($get_01 -ne $null) {
    $enable = Read-Host "Do you want to enable monitoring to instances with instance-id: $($get_01.InstanceId -join ' , ') ? (Y|N)" 
    write-Host "" 
    
        If($enable -eq "Y" -or $enabele -eq "y")
        {
            Start-EC2InstanceMonitoring -Region $region -InstanceId $get_01.InstanceId
            sleep -Seconds 5
        }
        
        Write-Host Monitoring was enabled for instances with IDs $($get_01.InstanceId) -ForegroundColor Yellow
        Write-Host ""
    }else{

        Write-Host "Your ec2 unstances in $region  have monitoring enabled" -ForegroundColor Blue
    }
    
}
    }
    ##*===============================================
    ##*S3 Monitoring
    ##*===============================================
    
    Write-Host ""
    $S3 = Read-Host "Do you want to configure S3 Monitoring? (Y|N)"
    Write-Host ""
$region = "us-east-1"
    IF ($S3 -eq "Y"){
    Write-Host "" -ForegroundColor Yellow
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "Server access logs are useful for many" -ForegroundColor Green
    Write-Host "applications, including understanding" -ForegroundColor Green
    Write-Host "security, access, and your Amazon S3 bill." -ForegroundColor Green       
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    
    
    $buckets = Get-S3Bucket -Region $region
    Write-Host ""
    foreach ($bucket in $buckets) {
        Write-Host "-----------------------------------------------------------" -ForegroundColor Blue
        Write-Host " BucketName: $($bucket.BucketName)" -ForegroundColor Green
        Write-Host "-----------------------------------------------------------" -ForegroundColor Blue

    }

    Write-Host ""

    $bucketname = Read-Host "Please select the bucket for S3 Monitoring configuration"

    $s3logs = Get-S3BucketLogging -BucketName $bucketname -Region $region

    Write-Host ""
   
    if ($s3logs.TargetBucketName -eq $null) {
    
        Write-Host Server access logging is currently disabled for bucket $($bucketname) -ForegroundColor Yellow
        Write-Host""
        $response = Read-Host "Do you want to enable Server access logging for this bucket? (y/n)"
        Write-Host""
    
            if ($response -eq "y") {
    
              
                $buckets = Get-S3Bucket -Region $region
                Write-Host "====================================================" -ForegroundColor Green
                Write-Host "You have to enter the name of the target bucket" -ForegroundColor Green
                Write-Host "where you want to store the logs and make sure to"-ForegroundColor Green
                Write-Host "select a bucket in the same region " -ForegroundColor Green
                Write-Host "====================================================" -ForegroundColor Green
                Write-Host ""
                foreach ($bucket in $buckets) {
                    Write-Host "-----------------------------------------------------------" -ForegroundColor Blue
                    Write-Host " BucketName: $($bucket.BucketName)" -ForegroundColor Green
                    Write-Host "-----------------------------------------------------------" -ForegroundColor Blue
            
                }
            
                Write-Host ""
                $targetBucket = Read-Host "please enter your choice"
                Write-Host ""
                
        
                Write-Host ""
                Write-Host "======================================================" -ForegroundColor Green
                Write-Host "If you store log files from multiple Amazon S3 buckets" -ForegroundColor Green
                Write-Host "in a single bucket, you can use a prefix to distinguish"  -ForegroundColor Green
                Write-Host "which log files came from which bucket."  -ForegroundColor Green
                Write-Host "======================================================" -ForegroundColor Green
                Write-Host ""
        
                $prefix = Read-Host "Enter the prefix for the log files (optional)"
                Write-Host ""
    
                
                Write-Host "Please select Log object key format" -ForegroundColor Green
                Write-Host ""
                Write-Host "1.TargetObjectKeyFormat_SimplePrefix" -ForegroundColor Green
                Write-Host ""
                Write-Host "Ex: [YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]" -ForegroundColor Yellow
                Write-Host ""
    
                Write-Host "2. PartitionedPrefix_PartitionDateSource" -ForegroundColor Green
                Write-Host ""
                Write-Host "Ex: [SourceAccountId]/​[SourceRegion]/​[SourceBucket]/​[YYYY]/​[MM]/​[DD]/​[YYYY]-[MM]-[DD]-[hh]-[mm]-[ss]-[UniqueString]" -ForegroundColor Yellow
                Write-Host ""
    
                $choice = Read-Host "Please enter your choice (1/2)"
    
                    IF($choice -eq "1"){
                        
                        Write-Host "To use the simple format for S3 keys for log objects. To specify SimplePrefix format, set SimplePrefix to {}." -ForegroundColor Yellow
                        $simple = New-Object -TypeName "Amazon.S3.Model.SimplePrefix"
                        $simple.Equals{$true}
                        Write-S3BucketLogging -BucketName $bucketName -LoggingConfig_TargetBucketName $targetBucket -LoggingConfig_TargetPrefix $prefix -TargetObjectKeyFormat_SimplePrefix $simple -Region $region
                        
                    } elseif($choice -eq "2"){
                        Write-Host "------------------------------------------------------------------" -ForegroundColor Green
                        Write-Host "There are two options:" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "1.S3 event time: The year, month, and day will"  -ForegroundColor Yellow
                        Write-Host "be based on the timestamp of the S3 event in"  -ForegroundColor Yellow
                        Write-Host "the file that's been delivered." -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "2.Log file delivery time: The year, month, and day" -ForegroundColor Yellow
                        Write-Host "will be based on the time when the log file was delivered to S3." -ForegroundColor Yellow
                        Write-Host "------------------------------------------------------------------" -ForegroundColor Green
                        Write-Host ""
    
    
                        $logObjectKeyFormats = @{
                            "1" = "EventTime";
                            "2" = "DeliveryTime";
                        }
    
                        Write-Host "Choose a log object key format for S3 server access logging:" -ForegroundColor Green
                        Write-Host ""
                        foreach ($key in $logObjectKeyFormats.Keys) {
                            Write-Host "  $key. $($logObjectKeyFormats[$key])" -ForegroundColor Yellow
                        }
    
                            ## Get the user's choice
                            $choice = Read-Host "Enter the number of your chosen format"
                            Write-Host ""
    
                            if ($choice -eq "1") {
                                $s3time = [Amazon.S3.PartitionDateSource]::EventTime
    
                                Write-Host "You chose: EventTime" -ForegroundColor Green
    
                            } elseif ($choice -eq "2") {
                                $s3time = [Amazon.S3.PartitionDateSource]::DeliveryTime
                                Write-Host "You chose: DeliveryTime" -ForegroundColor Green
                            } else {
                                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                                exit
                            }
                        }
    
                        Write-S3BucketLogging -BucketName $bucketName -LoggingConfig_TargetBucketName $targetBucket -LoggingConfig_TargetPrefix $prefix -PartitionedPrefix_PartitionDateSource $s3time -Region $region
    
            } else {
                Write-Host""
                Write-Host "Server access logging will remain disabled for bucket $bucketName"  -ForegroundColor Yellow
                Write-Host""
            }
    
    } else {
        Write-Host""
        Write-Host "Server access logging is already enabled for bucket $bucketName"   -ForegroundColor DarkMagenta
        Write-Host""
    }   
    
}
    
    
    ##*===============================================
    ##* RDS Monitoring
    ##*===============================================
    
    $RDS = Read-Host "Please enter Y if you want to configure RDS Monitoring"
    IF($RDS -eq "Y"){
    
    Write-Host "" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host "When you use RDS Performance Insights, you can visualize " -ForegroundColor Green
    Write-Host "the database load and filter the load by waits, SQL" -ForegroundColor Green
    write-host "statements, hosts, or users. This way, you can identify " -ForegroundColor Green
    Write-Host "which queries are causing issues and view the " -ForegroundColor Green
    Write-Host "wait type and wait events associated to that query." -ForegroundColor Green     
    Write-Host "===========================================================" -ForegroundColor Green
    
    $Enable = Read-Host "Please enter Y if you want to enable Performance Insights for your RDS database instance"
    
    If ($Enable -eq "Y"-or $Enable -eq "y"){
    ## Get all RDS instances
    $rdsInstances = Get-RDSDBInstance -Region eu-west-1 
    $instancesWithoutPI = @()
    
    foreach ($instance in $rdsinstances) {
       
        if (!$instance.PerformanceInsightsEnabled) {
           
            $instancesWithoutPI += [PSCustomObject]@{
                InstanceIdentifier = $instance.DBInstanceIdentifier
                Engine = $instance.Engine
                DBInstanceClass = $instance.DBInstanceClass
            }
        }
    }
    
    if ($instancesWithoutPI.Count -gt 0) {
        Write-Host "RDS instances without Performance Insights enabled:" -ForegroundColor Yellow
        $instancesWithoutPI | Format-Table -AutoSize
    } else {
        Write-Host "All RDS instances have Performance Insights enabled" -ForegroundColor Red
    }
       
    
    # Enable Performance Insights for all instances without it
    if ($instancesWithoutPI.Count -gt 0) {
        Write-Host "Enabling Performance Insights for the following instances:" -ForegroundColor Yellow
        foreach ($instance in $instancesWithoutPI) {
          
          if (!$instance.PerformanceInsightsEnabled) {
            Write-Host "Enabling Performance Insights for instance $($instance.DBInstanceIdentifier)"
           
            $result = Edit-RDSDBInstance -DBInstanceIdentifier $instance.InstanceIdentifier -EnablePerformanceInsight $true -Region eu-west-1
            if ($result.DBInstanceStatus -eq "modifying") {
                Write-Host "  - Performance Insights enabled for $($instance.InstanceIdentifier)" -ForegroundColor Green
            } else {
                Write-Host "  - Error enabling Performance Insights for $($instance.InstanceIdentifier)" -ForegroundColor Red
            }
        }
    }
    }
    
    }
    
    
    Write-Host "" -ForegroundColor Yellow
    Write-Host "====================================================================" -ForegroundColor Green
    Write-Host "Amazon RDS lets you export database logs to Amazon CloudWatch Logs." -ForegroundColor Green
    Write-Host "With CloudWatch Logs, you can perform real-time analysis of the" -ForegroundColor Green
    Write-Host "log data. You can also store the data in highly durable storage" 
    write-host "and manage the data with the ClouWatch Logs Agent." -ForegroundColor Green
    Write-Host "====================================================================" -ForegroundColor Green
    
    ## Get all RDS single instances
    $Enable = Read-Host "Please enter Y if you want to configure cloudwatch logs export for your RDS database instances"
    
    If ($Enable -eq "Y"-or $Enable -eq "y"){
    $singleInstances = Get-RDSDBInstance -Region eu-west-1 
    $instances = $singleinstances | Where-Object {$_.DBClusterIdentifier -eq $null}
    
    $instancesWithoutLogExports = @()
    
    foreach ($instance in $instances) {
    
        $logExports = $instance.EnabledCloudwatchLogsExports
    
        if (!$logExports) {
           
            $instancesWithoutLogExports += [PSCustomObject]@{
                InstanceIdentifier = $instance.DBInstanceIdentifier
                Engine = $instance.Engine
            }
        }
    }
    
    
            if ($instancesWithoutLogExports.Count -gt 0) {
                Write-Host "RDS instances without log exports enabled:" -ForegroundColor Yellow
                $instancesWithoutLogExports | Format-Table -AutoSize
            } else {
                Write-Host "All RDS instances have log exports enabled" -ForegroundColor Red
            }
    
     
            foreach ($instance in $instancesWithoutLogExports) {
                Write-Host "Select log types to export for instance $($instance.InstanceIdentifier):" -ForegroundColor Yellow
    
                
                $engine = $instance.Engine
    
                # Define the available log types based on the database engine
                if ($engine -eq "aurora-mysql" -or $engine -eq "mariadb" -or $engine -eq "mysql" ) {
                    $logTypes = @("audit", "error", "general", "slowquery")
                } elseif ($engine -eq "postgresql") {
                    $logTypes = @("postgresql_log", "upgrade_log")
                } elseif ($engine -eq "oracle") {
                    $logTypes = @("alert_log", "audit_log", "listener_log", "trace_log" , "Oracle_Management_Agent_log")
                } elseif ($engine -eq "aurora-postgresql") {
                    $logTypes = @("postgresql")
                } elseif ($engine -eq "sqlserver") {
                    $logTypes = @("error_log")
                } else {    
                    Write-Host "Unsupported database engine: $($instance.Engine)" -ForegroundColor Red
                    continue
                }
    
                # Ask the user to select the log types
                $selectedLogTypes = @()
                foreach ($logType in $logTypes) {
                    $response = Read-Host "Export $($logType)? (y/n)"
                    if ($response -eq "y") {
                        $selectedLogTypes += $logType
                    }
                }
    
                # Enable log exports for the instance
                if ($selectedLogTypes.Count -gt 0) {
                    $modifyDbInstanceParams = @{
                        DBInstanceIdentifier = $instance.InstanceIdentifier
                        CloudwatchLogsExportConfiguration_EnableLogType = $selectedLogTypes
                        }
                    }
                    $result = Edit-RDSDBInstance @modifyDbInstanceParams -Region eu-west-1
                    while ($result.DBInstanceStatus -ne "available") {
                        write-host " CloudWatch Logs configuration is in progress" -ForegroundColor Red
                    }
                    if ($result.DBInstanceStatus -eq "available") {
                        Write-Host "Log exports enabled for instance $($instance.InstanceIdentifier)" -ForegroundColor Green
                    } else {
                        Write-Host "Error enabling log exports for instance $($instance.InstanceIdentifier)" -ForegroundColor Red
                    }
                        }
    }
    ## ## Get all RDS clusters      
    $Enable = Read-Host "Please enter Y if you want to configure cloudwatch logs export for your RDS database clusters"
    
    If ($Enable -eq "Y"-or $Enable -eq "y"){
    $clusters = Get-RDSDBCluster -Region eu-west-1 
    
    $clustersWithoutLogExports = @()
    
    foreach ($cluster in $clusters) {
    
        $logExports = $cluster.EnabledCloudwatchLogsExports
    
        if (!$logExports) {
            
                $clustersWithoutLogExports  += [PSCustomObject]@{
                DBClusterIdentifier  = $cluster.DBClusterIdentifier 
                Engine = $cluster.Engine
            }
        }
    }
    
    
            if ($clustersWithoutLogExports.Count -gt 0) {
                Write-Host "RDS instances without log exports enabled:" -ForegroundColor Yellow
                $clustersWithoutLogExports | Format-Table -AutoSize
            } else {
                Write-Host "All RDS clusters have log exports enabled" -ForegroundColor Red
            }
    
            # Ask the user to select which logs to export for each instance
            foreach ($cluster in $clustersWithoutLogExports) {
                Write-Host "Select log types to export for instance $($cluster.DBClusterIdentifier):" -ForegroundColor Yellow
    
                # Get the database engine
                $engine = $cluster.Engine
    
                # Define the available log types based on the database engine
                if ($engine -eq "aurora-mysql" -or $engine -eq "mariadb" -or $engine -eq "mysql" ) {
                    $logTypes = @("audit", "error", "general", "slowquery")
                } elseif ($engine -eq "postgresql") {
                    $logTypes = @("postgresql_log", "upgrade_log")
                } elseif ($engine -eq "oracle") {
                    $logTypes = @("alert_log", "audit_log", "listener_log", "trace_log" , "Oracle_Management_Agent_log")
                } elseif ($engine -eq "aurora-postgresql") {
                    $logTypes = @("postgresql")
                } elseif ($engine -eq "sqlserver") {
                    $logTypes = @("error_log")
                } else {    
                    Write-Host "Unsupported database engine: $($instance.Engine)" -ForegroundColor Red
                    continue
                }
    
                # Ask the user to select the log types
                $selectedLogTypes = @()
                foreach ($logType in $logTypes) {
                    $response = Read-Host "Export $($logType)? (y/n)"
                    if ($response -eq "y") {
                        $selectedLogTypes += $logType
                    }
                }
    
                # Enable log exports for the instance
                if ($selectedLogTypes.Count -gt 0) {
                    $modifyDbInstanceParams = @{
                        DBClusterIdentifier  = $cluster.DBClusterIdentifier
                        CloudwatchLogsExportConfiguration_EnableLogType = $selectedLogTypes
                        }
                    }
                    $result = Edit-RDSDBCluster @modifyDbInstanceParams -Region eu-west-1
                    while ($result.DBInstanceStatus -ne "available") {
                        write-host " CloudWatch Logs configuration is in progress" -ForegroundColor Red
                        sleep -Seconds 5
                    }
                    if ($result.DBInstanceStatus -eq "available") {
                        Write-Host "Log exports enabled for instance $($instance.InstanceIdentifier)" -ForegroundColor Green
                    } else {
                        Write-Host "Error enabling log exports for instance $($instance.InstanceIdentifier)" -ForegroundColor Red
                    }
                }
            }            
    
    Write-Host "" -ForegroundColor Yellow
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host "Enabling Enhanced Monitoring metrics are useful when you want" -ForegroundColor Green
    Write-Host "to see how different processes or threads use the CPU" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    
    # Get all RDS instances
    $instances = Get-RDSDBInstance -Region $region
    
    $instancesWithoutEnhancedMonitoring = @()
    
    
    foreach ($instance in $instances) {
        
        $monitoringRoleArn = $instance.MonitoringRoleArn
    
        if (!$monitoringRoleArn) {
           
            $instancesWithoutEnhancedMonitoring += [PSCustomObject]@{
                InstanceIdentifier = $instance.DBInstanceIdentifier
                Engine = $instance.Engine
            }
        }
    }
    
    if ($instancesWithoutEnhancedMonitoring.Count -gt 0) {
        Write-Host "RDS instances without Enhanced Monitoring enabled:" -ForegroundColor Yellow
        $instancesWithoutEnhancedMonitoring | Format-Table -AutoSize
    } else {
        Write-Host "All RDS instances have Enhanced Monitoring enabled" -ForegroundColor Red
    }
    
    
    ###enable Enhanced Monitoring for each instance
    foreach ($instance in $instancesWithoutEnhancedMonitoring) {
        $response = Read-Host "Enable Enhanced Monitoring for instance $($instance.InstanceIdentifier)? (y/n)"
        if ($response -eq "y") {
            
    
            $monitoringInterval = Read-Host "Enter the monitoring interval (in seconds):  [0, 1, 5, 10, 15, 30, 60]"
            $modifyDbInstanceParams = @{
                DBInstanceIdentifier = $instance.InstanceIdentifier
                MonitoringInterval = $monitoringInterval
                MonitoringRoleArn = "arn:aws:iam::571263213847:role/rds-monitoring-role"
            }
            $result = Edit-RDSDBInstance  @modifyDbInstanceParams -Region eu-west-1
            if ($result.MonitoringInterval -ne $null) {
                Write-Host "Enhanced Monitoring enabled for instance $($instance.InstanceIdentifier) with monitoring interval of $($monitoringInterval) seconds" -ForegroundColor Green
            } else {
                Write-Host "Error enabling Enhanced Monitoring for instance $($instance.InstanceIdentifier)" -ForegroundColor Red
            }
        }
    }
    }
    
   
    
    ##*===============================================
    ##* Lambda Functions Monitoring
    ##*===============================================
    Write-Host ""
    $Functions = Read-Host "Please enter Y if you want to configure Lambda Functions Monitoring"
    IF ($Functions -eq "Y"){

    $functions = Get-LMFunctionList -Region $region
    
    Write-Host ""
    Write-Host There are $($functions.Count) functions in $region which are: $($functions.FunctionName -join ', ') -ForegroundColor Green
    Write-Host ""
    
    
    
    Write-Host "=============================================================" -ForegroundColor Green
    write-host "The function's Amazon CloudWatch Logs configuration settings" -ForegroundColor Green
    Write-Host "=============================================================" -ForegroundColor Green
    
    $configure= Read-Host "Please enter Y if you want to configure cloudwatch logs export for your AWS Lambda Function"
    if ($configure -eq "y" -or $configure -eq "Y") {
    
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Set this property to filter the application logs" -ForegroundColor Green
    Write-Host "for your function that Lambda sends to CloudWatch." -ForegroundColor Green
    write-host "Lambda only sends application logs at the selected level"
    Write-Host "of detail and lower, where TRACE is the"  -ForegroundColor Green
    write-Host "highest level and FATAL is the lowest."  -ForegroundColor Green 
    Write-Host "=============================================" -ForegroundColor Green
    
    $applogs = @("DEBUG" , "ERROR" , "FATAL" , "INFO" , "TRACE" , "WARN")
    
    $selectedLogTypes = @()
                foreach ($applog in $applogs) {
                    $response = Read-Host "Select $($applog)? (y/n)"
                    if ($response -eq "y") {
                        $selectedLogTypes += $applog
                    }
                }
            
    
            }
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "You can configure the format in which Lambda sends your" -ForegroundColor Green
    Write-Host "function's application and system logs to CloudWatch." -ForegroundColor Green
    Write-Host "Select between plain text and structured JSON." -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green            
                
    $configure= Read-Host "Please enter Y if you want to configure the property LogFormat for your AWS Lambda Function"
    if ($configure -eq "y" -or $configure -eq "Y") {
        $formattypes = @("JSON" , "Text")
        
        $selectedformattype  = @()
        foreach ($formattype in $formattypes) {
    
                    $response = Read-Host "Please Select $($formattype)? (y/n)"
                    if ($response -eq "y") {
                        $selectedformattype = $formattype
                    }
                }
            }
    
    
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host "The name of the Amazon CloudWatch log group the function sends logs to." -ForegroundColor Green
    Write-Host "By default, Lambda functions send logs" -ForegroundColor Green
    Write-Host "to a default log group named /aws/lambda/. You can use an existing log group" -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green     
    
    $selectloggroup = Read-Host "If you want to use an existing log group, Please enter Y"
    
            if ($selectloggroup -eq "Y" -or $selectloggroup -eq "y") {
                $loggroups = Get-CWLLogGroup -Region $region| Select-Object LogGroupName
    
                $selectedgroup = Read-Host "please enter the log group name you want"
            }
    
    Write-Host "=======================================================================" -ForegroundColor Green
    Write-Host "You can configure the property SystemLogLevel to filter the system logs" -ForegroundColor Green
    Write-Host "for your function that Lambda sends to CloudWatch." -ForegroundColor Green
    Write-Host "Lambda only sends system logs at the selected level of detail and lower,"
    Write-Host "where DEBUG is the highest level and WARN is the lowest." -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green  
    
    
    $configure= Read-Host "Please enter Y if you want to configure the property SystemLogLevel for your AWS Lambda Function"
    if ($configure -eq "y" -or $configure -eq "Y") {
    
        $syslogs = @("DEBUG" , "INFO" , "WARN")
    
        $sysLogTypes = @()
                foreach ($syslog in $syslogs) {
                    $response = Read-Host "Select $($syslog)? (y/n)"
                    if ($response -eq "y") {
                        $sysLogTypes += $syslog
                    }
                }
    }
    $listFun = Get-LMFunctionList -Region $region 
    Write-Host ($($listFun.FunctionName) -join ' , ') -ForegroundColor Yellow
    Write-Host ""
    $selectedfunction = Read-Host "Please select the lambda function you want to update"
    
    
    
    Update-LMFunctionConfiguration -FunctionName  $selectedfunction -Region $region  -LoggingConfig_ApplicationLogLevel $selectedLogTypes -LoggingConfig_SystemLogLevel $sysLogTypes -LoggingConfig_LogFormat $formattype -LoggingConfig_LogGroup $selectedgroup
    
    
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "You can use AWS X-Ray to visualize the components of your application," -ForegroundColor Green
    Write-Host "identify performance bottlenecks," -ForegroundColor Green
    Write-Host "and troubleshoot requests that resulted in an error. " -ForegroundColor Green
    Write-Host "=======================================================================" -ForegroundColor Green  
    
    
    $Enable = Read-Host "Please enter Y if you want to use AWS X-Ray for your AWS Lambda Function"
    if ($Enable -eq "y" -or $Enable -eq "Y") {
        $listFun = Get-LMFunctionList -Region $TargetRegion
        $getfuns = Write-Host $listFun.FunctionName
        $selectedfunction = Read-Host "Please select the lambda function you want to update"
        Update-LMFunctionConfiguration -FunctionName $selectedFunctions -TracingConfig_Mode Active -Region $TargetRegion
    }
            
    }
    
   
    ##*===============================================
    ##* Auto Scaling Group Monitoring
    ##*===============================================
    Write-Host ""
    $scaling_group = Read-Host "Please enter Y if you want to configure  Auto Scaling Group Monitoring"
    IF( $scaling_group  -eq "Y"){

    $list = Get-ASAutoScalingGroup -Region eu-west-1 | Select-Object  AutoScalingGroupName  
    Write-Host You have $list.Count auto scaling group which are ($list.AutoScalingGroupName -join ' , ')   -ForegroundColor Yellow 
    $list = Get-ASAutoScalingGroup -Region eu-west-1 | Select-Object  AutoScalingGroupName , EnabledMetrics 
    $get = $list | Where-Object {$_.EnabledMetrics -ne $null}
    
        if ( $get.Count -gt 0) {
            Write-Host ""
            Write-Host ($get.AutoScalingGroupName -join ' , ')  enable group metrics collection within CloudWatch -ForegroundColor Yellow
        
        } else {
            Write-Host ""
            write-Host None of auto scaling groups enable group metrics collection within CloudWatch -ForegroundColor Yellow 
        }
    
    
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Green
    Write-Host "By enabling group metrics collection, you get increased visibility" -ForegroundColor Green
    Write-Host "into the history of your Auto Scaling group, such as changes" -ForegroundColor Green
    Write-Host "in the size of the group over time. The metrics are available" -ForegroundColor Green
    Write-Host "at a 1-minute granularity at no additional charge," -ForegroundColor Green
    Write-Host "but you must turn them on." -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green  
    Write-Host ""
    
    
    
    $asGroups = Get-ASAutoScalingGroup -Region $TargetRegion
    $groupsWithoutMetrics = @()
    
    foreach ($asGroup in $asGroups) {
        if ($asGroup.EnabledMetrics.Count -eq 0) {
            $groupsWithoutMetrics += $asGroup
        }
    }
    
    if ($groupsWithoutMetrics.Count -gt 0) {
        Write-Host "The following Auto Scaling groups do not have metrics collection enabled:" -ForegroundColor Yellow
        write-host ($groupsWithoutMetrics.AutoScalingGroupName -join ' , ') -ForegroundColor red
    
        $enableMetrics = Read-Host "Do you want to enable metrics collection for these groups? (Y/N) "
    
        if ($enableMetrics -eq "y" -or $enableMetrics -eq "Y") {
            $i = 0
            while ($i -lt $groupsWithoutMetrics.Count) {
                $group = $groupsWithoutMetrics[$i]
                Write-Host""
                Write-Host "Enabling metrics collection for $($group.AutoScalingGroupName)..." -ForegroundColor Green
    
                Enable-ASMetricsCollection -Region $region -AutoScalingGroupName $group.AutoScalingGroupName -Granularity 1Minute
                Write-Host""
                Write-Host "Metrics collection enabled for $($group.AutoScalingGroupName)"
                $i++
            }
        } else {
            Write-Host "Metrics collection not enabled."
        }
    } else {
        Write-Host "All Auto Scaling groups have metrics collection enabled" -ForegroundColor Yellow
    }           
    
    
}
       
    
    ##*===============================================
    ##* ECS Clusters Monitoring
    ##*===============================================
    
  $ECS = Read-Host "Please enter Y if you want to configure ECS Clusters Monitoring"

    IF($ECS -eq "Y") {

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "Container Insights is turned off by default. When you use" -ForegroundColor Green
    Write-Host "Container Insights, there is a cost associated with it." -ForegroundColor Green
    Write-Host "CloudWatch automatically collects metrics for many resources," -ForegroundColor Green
    Write-Host "such as CPU, memory, disk, and network. Container" -ForegroundColor Green
    Write-Host "Insights also provides diagnostic information, such as container" -ForegroundColor Green
    Write-Host "restart failures, that you use to isolate issues" -ForegroundColor Green
    Write-Host "and resolve them quickly. You can also set CloudWatch alarms on" -ForegroundColor Green
    Write-Host "metrics that Container Insights collects." -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Green  
    Write-Host ""
    
    $Enable = Read-Host "Please enter Y if you want to turn on Container Insights for ECS Clusters"
    if ($Enable  -eq "y" -or $Enable -eq "Y"){
    
    $update = New-Object -TypeName   Amazon.ECS.Model.ClusterSetting
    $update.Name = "ContainerInsights"
    $update.Value = "enabled"
    
    $clusters = Get-ECSClusterList  -Region $region
    
    
        $i = 0
        while ($i -lt $clusters.Count) {
            $enableinsights = $clusters[$i]
            Write-Host""
            Write-Host "Enabling Container Insights for: $($clusters[$i -1])" -ForegroundColor Green
        
            $enable = Update-ECSClusterSetting -Cluster $clusters[$i -1] -Setting $update -Region $TargetRegion
            Write-Host""
            Write-Host "Container Insights Enabled for: $($clusters[$i -1])"
            $i++
        }
    }
    }
    
        ##################################################################
        ##*                            END
        ##################################################################
    
        Write-Host ""
        Write-Host "=======================================================" -ForegroundColor Green
        Write-Host "Configuring AWS resources mountring has been Completed" -ForegroundColor Green
        Write-Host "=======================================================" -ForegroundColor Green
}


######################################################
##              Questions
######################################################

Write-Host ""
$q1 = Read-Host "Do You Want to Proceed with CloudTrail?(Y/N)"
Write-Host " "
if($q1 -eq "y"){
   CloudTrail_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q2 = Read-Host "Do You Want to Proceed with GuardDuty?(Y/N)"
Write-Host " "
if($q2 -eq "y"){
       GuardDuty_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q3 = Read-Host "Do You Want to Proceed with AWS Config?(Y/N)"
Write-Host " "
if($q3 -eq "y"){
        AWSConfig_fun   
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q4 = Read-Host "Do You Want to Proceed with AWS Security Hub?(Y/N)"
Write-Host " "
if($q4 -eq "y"){
       securityHub_fun   
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q5 = Read-Host "Do You Want to Proceed with Amazon Macie?(Y/N)"
Write-Host " "
if($q5 -eq "y"){
       Macie_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q6 = Read-Host "Do You Want to Proceed with AWS Well-Architect?(Y/N)"
Write-Host " "
if($q6 -eq "y"){
       WellArchitect_fun    
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q7 = Read-Host "Do You Want to Proceed with AWS Audit Manager?(Y/N)"
Write-Host " "
if($q7 -eq "y"){
       AuditManager_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
   
$q10 = Read-Host "Do You Want to Proceed with AWS Cognito Service?(Y/N)"
Write-Host " "
if($q10 -eq "y"){
      Cognito_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q11 = Read-Host "Do You Want to Proceed with AWS Inspector Service?(Y/N)"
Write-Host " "
if($q11 -eq "y"){
       Inspector_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   


$q12 = Read-Host "Do You Want to Proceed with AWS Detective Service?(Y/N)"
Write-Host " "
if($q12 -eq "y"){
    Detective_fun
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "

$q13 = Read-Host "Do You Want to Proceed with AWS CloudWatch alarms?(Y/N)"
Write-Host " "
if($q13 -eq "y"){
       aws-clouwatch 
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "
   
$q14 = Read-Host "Do You Want to Proceed with Aws Artifact(Y/N)"
Write-Host " "
if($q14 -eq "y"){
        aws_artifact
}
Write-Host "----------------------------------------------------------- " -ForegroundColor Yellow
Write-Host " "

$q15 = Read-Host "Do You Want to Proceed with Aws Resources Monitoring?(Y/N)"
Write-Host " "
if($q15 -eq "y"){
        awsresources_mountring
}
   
   




Write-Host "" -ForegroundColor Yellow

Write-Host " " -ForegroundColor Yellow
Write-Host " " -ForegroundColor Yellow
Write-Host "###############################################################"-ForegroundColor Blue
Write-Host "  AWS Security Assesment Automation " -ForegroundColor Yellow
Write-Host "###############################################################" -ForegroundColor Blue
Write-Host "###############################################################" -ForegroundColor Blue
Write-Host "   Licensed by Infrastructure Consulatant\  Khaled Mohamed Assasa  -ForegroundColor White
Write-Host "###############################################################
###############################################################
############################################################### " -ForegroundColor Blue
Write-Host "                      Thank You !!!" -ForegroundColor White
Write-Host "############################################################### " -ForegroundColor Blue
