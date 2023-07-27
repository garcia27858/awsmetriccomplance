#!/usr/bin/env python3
import os

# Description: This script will ask the user a series of questions to help them setup their environment.
def awsconfigchanges():
    print("Creating metric filter to check for AWS Config configuration changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'aws_config_changes_metric' --metric-transformations metricName='aws_config_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }' --profile " + profile + " --region " + region + " --output text")

def awsconfigchangesalarm():
    print("Creating alarm for the metric filter to check for AWS Config configuration changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'aws_config_changes_alarm' --metric-name 'aws_config_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def apiunauthorizedcall():
    print("Creating metric filter to check for API unauthorized calls")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "'  --filter-name 'unauthorized_api_calls_metric' --metric-transformations metricName='unauthorized_api_calls_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.errorCode = '*UnauthorizedOperation') || ($.errorCode = 'AccessDenied*') || ($.sourceIPAddress!='delivery.logs.amazonaws.com') || ($.eventName!='HeadBucket') }' --profile " + profile + " --region " + region + " --output text")

def apiunauthorizedcallalarm():
    print("Creating alarm for the metric filter to check for API unauthorized calls")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'unauthorized_api_calls_alarm' --metric-name 'unauthorized_api_calls_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def cloudtrailconfigchanges():
    print("Creating metric filter to check for CloudTrail configuration changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'cloudtrail_config_changes_metric' --metric-transformations metricName='cloudtrail_config_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' --profile " + profile + " --region " + region + " --output text")

def cloudtrailconfigchangesalarm():
    print("Creating alarm for the metric filter to check for CloudTrail configuration changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'cloudtrail_config_changes_alarm' --metric-name 'cloudtrail_config_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def consolesigninfailure():
    print("Creating metric filter to check for console sign-in failures")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'console_signin_failure_metric' --metric-transformations metricName='console_signin_failure_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }' --profile " + profile + " --region " + region + " --output text")

def consolesigninfailurealarm():
    print("Creating alarm for the metric filter to check for console sign-in failures")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'console_signin_failure_metric'' --metric-name 'console_signin_failure_metric'' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def disableordeletecmk():
    print("Creating metric filter to check for disabling or deleting customer created CMKs")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'disable_or_delete_cmk_metric' --metric-transformations metricName='disable_or_delete_cmk_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }' --profile " + profile + " --region " + region + " --output text")

def disableordeletecmkalarm():
    print("Creating alarm for the metric filter to check for disabling or deleting customer created CMKs")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'disable_or_delete_cmk_alarm' --metric-name 'disable_or_delete_cmk_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def iamchanges():
    print("Creating metric filter to check for IAM policy changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'iam_changes_metric' --metric-transformations metricName='iam_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}' --profile " + profile + " --region " + region + " --output text")

def iamchangesalarm():
    print("Creating alarm for the metric filter to check for IAM policy changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'iam_changes_alarm' --metric-name 'iam_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def naclchanges():
    print("Creating metric filter to check for network access control list (NACL) changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'nacl_changes_metric' --metric-transformations metricName='nacl_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }' --profile " + profile + " --region " + region + " --output text")

def naclchangesalarm():
    print("Creating alarm for the metric filter to check for network access control list (NACL) changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'nacl_changes_alarm' --metric-name 'nacl_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def networkgwchanges():
    print("Creating metric filter to check for network gateway changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'network_gw_changes_metric' --metric-transformations metricName='network_gw_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }' --profile " + profile + " --region " + region + " --output text")

def networkgwchangesalarm():
    print("Creating alarm for the metric filter to check for network gateway changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'network_gw_changes_alarm' --metric-name 'network_gw_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def nomfaconsolesignin():
    print("Creating metric filter to check for non-MFA console sign-in events")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'nomfa_console_signin_metric' --metric-transformations metricName='nomfa_console_signin_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = 'ConsoleLogin') && ($.additionalEventData.MFAUsed != 'Yes') && ($.userIdentity.type = 'IAMUser') && ($.responseElements.ConsoleLogin = 'Success') }' --profile " + profile + " --region " + region + " --output text")

def nomfaconsolesignalarm():
    print("Creating alarm for the metric filter to check for non-MFA console sign-in events")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'nomfa_console_signin_alarm' --metric-name 'nomfa_console_signin_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def orgchanges():
    print("Creating metric filter to check for AWS organization changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'org_changes_metric' --metric-transformations metricName='org_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = 'AcceptHandshake') || ($.eventName = 'AttachPolicy') || ($.eventName = 'CreateAccount') || ($.eventName = 'CreateOrganizationalUnit') || ($.eventName = 'CreatePolicy') || ($.eventName = 'DeclineHandshake') || ($.eventName = 'DeleteOrganization') || ($.eventName = 'DeleteOrganizationalUnit') || ($.eventName = 'DeletePolicy') || ($.eventName = 'DetachPolicy') || ($.eventName = 'DisablePolicyType') || ($.eventName = 'EnablePolicyType') || ($.eventName = 'InviteAccountToOrganization') || ($.eventName = 'LeaveOrganization') || ($.eventName = 'MoveAccount') || ($.eventName = 'RemoveAccountFromOrganization') || ($.eventName = 'UpdatePolicy') || ($.eventName = 'UpdateOrganizationalUnit')) }' --profile " + profile + " --region " + region + " --output text")

def orgchangesalarm():
    print("Creating alarm for the metric filter to check for AWS organization changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'org_changes_alarm' --metric-name 'org_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --alarm-actions '" + snsarn + "' --profile " + profile + " --region " + region + " --output text")

def rootusage():
    print("Creating metric filter to check for root usage")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'root_usage_metric' --metric-transformations metricName='root_usage_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ $.userIdentity.type = 'Root' && $.userIdentity.invokedBy NOT EXISTS && $.eventType != 'AwsServiceEvent' }' --profile " + profile + " --region " + region + " --output text")

def rootusagealarm():
    print("Creating alarm for the metric filter to check for root usage")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'root_usage_alarm' --metric-name 'root_usage_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark' --profile " + profile + " --region " + region + " --output text")

def routetablechanges():
    print("Creating metric filter to check for route table changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'route_table_changes_metric' --metric-transformations metricName='route_table_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }' --profile " + profile + " --region " + region + " --output text")

def routetablechangesalarm():
    print("Creating alarm for the metric filter to check for route table changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'route_table_changes_alarm' --metric-name 'route_table_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark'  --profile " + profile + " --region " + region + " --output text")

def s3policychanges():
    print("Creating metric filter to check for S3 bucket policy changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 's3_policy_changes_metric' --metric-transformations metricName='s3_policy_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }' --profile " + profile + " --region " + region + " --output text")

def s3policychangesalarm():
    print("Creating alarm for the metric filter to check for S3 bucket policy changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 's3_policy_changes_alarm' --metric-name 's3_policy_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark'  --profile " + profile + " --region " + region + " --output text")

def securitygroupchanges():
    print("Creating metric filter to check for security group changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'security_group_changes_metric' --metric-transformations metricName='security_group_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }' --profile " + profile + " --region " + region + " --output text")

def securitygroupchangesalarm():
    print("Creating alarm for the metric filter to check for security group changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'security_group_changes_alarm' --metric-name 'security_group_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark'  --profile " + profile + " --region " + region + " --output text")

def vpcchanges():
    print("Creating metric filter to check for VPC changes")
    os.system("aws logs put-metric-filter --log-group-name '" + ctgn + "' --filter-name 'vpc_changes_metric' --metric-transformations metricName='vpc_changes_metric',metricNamespace='CISBenchmark',metricValue=1 --filter-pattern '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }' --profile " + profile + " --region " + region + " --output text")

def vpcchangesalarm():
    print("Creating alarm for the metric filter to check for VPC changes")
    os.system("aws cloudwatch put-metric-alarm --alarm-name 'vpc_changes_alarm' --metric-name 'vpc_changes_metric' --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --namespace 'CISBenchmark'  --profile " + profile + " --region " + region + " --output text")

#Ask the user if they have multiple aws profiles and if so, which one they want to use.
#If they only have one profile, then use that one.
#If they have multiple profiles, then ask them which one they want to use.
profile = input("Do you have multiple AWS profiles? (y/n): ")
if profile == "y":
    profile = input("Which profile do you want to use? (default): ")
    if profile == "default":
        print("Using default profile")
    else:
        print("Using " + profile + " profile")
else:
    print("Using default profile")

#Ask the user if they have a cloudtrail group name and if so, which one they want to use.
#If they only have one cloudtrail group name, then use that one. They can not use default.
#If not, bail.
ctgn = input("Do you have a cloudtrail group name? (y/n): ")
if ctgn == "y":
    ctgn = input("Which cloudtrail group name do you want to use?")
    if ctgn == "default":
        print("You must specify a cloudtrail group name")
    else:
        print("Using " + ctgn + " cloudtrail group name")
else:
    print("You must specify a cloudtrail group name")

#Ask the user if they want to use a specific region and if so, which one they want to use.
#If they only have one region, then use that one.
region = input("Please specify the region where the cloud trail log group exist: (example: us-east-1))")
if region == "us-east-1":
    print("Using us-east-1 region")
else:
    print("Using " + region + " region")

#Ask the user what their sns_topic_arn is.
snsarn = input("Please specify the sns topic arn where the cloud trail log group exist: (example: arn:aws:sns:us-west-2:806758022664:NotifyMe))")
if snsarn == "arn:aws:sns:us-west-2:806758022664:NotifyMe":
    print("Using arn:aws:sns:us-west-2:806758022664:NotifyMe")
else:
    print("Using " + snsarn + " sns topic arn")

#Ask the user if they want to run all of the functions or just a specific one.
#If they select all, then run all of the functions and not the functions that create the alarms.
#If they select specific, then ask them which function they want to run.
metricquestion = input("Do you want to run all of the functions or just a specific one? (all/specific): ")
if metricquestion == "all":
    awsconfigchanges()
    apiunauthorizedcall()
    cloudtrailconfigchanges()
    consolesigninfailure()
    disableordeletecmk()
    iamchanges()
    naclchanges()
    networkgwchanges()
    nomfaconsolesignin()
    orgchanges()
    rootusage()
    routetablechanges()
    s3policychanges()
    securitygroupchanges()
    vpcchanges()
elif metricquestion == "specific":
    whichfunction = input("Which metric do you want to run? (awsconfigchanges/apiunauthorizedcall/cloudtrailconfigchanges/consolesigninfailure/disableordeletecmk/iamchanges/naclchanges/networkgwchanges/nomfaconsolesignin/orgchanges/rootusage/routetablechanges/s3policychanges/securitygroupchanges/vpcchanges): ")
    if whichfunction == "awsconfigchanges":
        awsconfigchanges()
    elif whichfunction == "apiunauthorizedcall":
        apiunauthorizedcall()
    elif whichfunction == "cloudtrailconfigchanges":
        cloudtrailconfigchanges()
    elif whichfunction == "consolesigninfailure":
        consolesigninfailure()
    elif whichfunction == "disableordeletecmk":
        disableordeletecmk()
    elif whichfunction == "iamchanges":
        iamchanges()
    elif whichfunction == "naclchanges":
        naclchanges()
    elif whichfunction == "networkgwchanges":
        networkgwchanges()
    elif whichfunction == "nomfaconsolesignin":
        nomfaconsolesignin()
    elif whichfunction == "orgchanges":
        orgchanges()
    elif whichfunction == "rootusage":
        rootusage()
    elif whichfunction == "routetablechanges":
        routetablechanges()
    elif whichfunction == "s3policychanges":
        s3policychanges()
    elif whichfunction == "securitygroupchanges":
        securitygroupchanges()
    elif whichfunction == "vpcchanges":
        vpcchanges()
    else:
        print("Invalid input. Please try again.")
else:
    print("Invalid input. Please try again.")

#Ask the user if they want to create alarms for the all of the metric filters or a specific one.
#If they select all, then run all of the functions that create the alarms.
#If they select specific, then ask them which function they want to run.
alarmquestion = input("Do you want to create alarms for all of the metric filters or a specific one? (all/specific): ")
if alarmquestion == "all":
    apiunauthorizedcallalarm()
    awsconfigchangesalarm()
    cloudtrailconfigchangesalarm()
    consolesigninfailurealarm()
    disableordeletecmkalarm()
    iamchangesalarm()
    naclchangesalarm()
    networkgwchangesalarm()
    nomfaconsolesignalarm()
    orgchangesalarm()
    rootusagealarm()
    routetablechangesalarm()
    s3policychangesalarm()
    securitygroupchangesalarm()
    vpcchangesalarm()
elif alarmquestion == "specific":
    whichalarm = input("Which alarm do you want to run? (apiunauthorizedcallalarm/awsconfigchangesalarm/cloudtrailconfigchangesalarm/consolesigninfailurealarm/disableordeletecmkalarm/iamchangesalarm/naclchangesalarm/networkgwchangesalarm/nomfaconsolesignalarm/orgchangesalarm/rootusagealarm/routetablechangesalarm/s3policychangesalarm/securitygroupchangesalarm/vpcchangesalarm): ")
    if whichalarm == "apiunauthorizedcallalarm":
        apiunauthorizedcallalarm()
    elif whichalarm == "awsconfigchangesalarm":
        awsconfigchangesalarm()
    elif whichalarm == "cloudtrailconfigchangesalarm":
        cloudtrailconfigchangesalarm()
    elif whichalarm == "consolesigninfailurealarm":
        consolesigninfailurealarm()
    elif whichalarm == "disableordeletecmkalarm":
        disableordeletecmkalarm()
    elif whichalarm == "iamchangesalarm":
        iamchangesalarm()
    elif whichalarm == "naclchangesalarm":
        naclchangesalarm()
    elif whichalarm == "networkgwchangesalarm":
        networkgwchangesalarm()
    elif whichalarm == "nomfaconsolesignalarm":
        nomfaconsolesignalarm()
    elif whichalarm == "orgchangesalarm":
        orgchangesalarm()
    elif whichalarm == "rootusagealarm":
        rootusagealarm()
    elif whichalarm == "routetablechangesalarm":
        routetablechangesalarm()
    elif whichalarm == "s3policychangesalarm":
        s3policychangesalarm()
    elif whichalarm == "securitygroupchangesalarm":
        securitygroupchangesalarm()
    elif whichalarm == "vpcchangesalarm":
        vpcchangesalarm()
    else:
        print("Invalid input. Please try again.")
else:
    print("Invalid input. Please try again.")