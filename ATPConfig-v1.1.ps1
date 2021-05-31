<#
#################################################
## Advanced Threat Protection Configuration Master v5.2021 (Updated and Tested 5/18/2021)
#################################################

This script automates a lot of the set up process of M365 ATP and Exchange Online.
This script is safe to run after communicating ATP to the client and should have none, if any end-user disruption.
The following items will be configured automatically:


!! Make sure to connect to each module and follow all pre-requisites !!


    Connect to Exchange Online via PowerShell using MFA (Connect-ExchangeOnline)
    https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

    Connect to Azure Active Directory via PowerShell using MFA (Connect-MsolService)
    https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0

    Connect to Azure Active Directory Preview Service via Powershell using MFA (Connect-AzureAD)
    https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0

    Connect to the Microsoft Graph API Service via Powershell using MFA (Connect-MSGraph)

#>


#################################################
## Pre-Reqs
#################################################

    $Answer = Read-Host "Have you connected all the required PowerShell CMDlets? Y/N "
        if ($Answer -eq 'n' -or $Answer -eq 'no') {

    #################################################
    ## Connecting Modules
    #################################################

                Write-Host -foregroundcolor yellow "Connecting Modules (ExchangeOnline, MSOL, AzureAD, MSGraph) ..."

                Connect-ExchangeOnline

                Connect-MsolService
                
                Connect-AzureAD
                
                Connect-MSGraph

    } else {


#################################################
## Loading Variables
#################################################

        $MessageColor = "Green"
        $AssessmentColor = "Yellow"

        $AlertAddress = Read-Host "Enter the Customer's ADMIN EMAIL ADDRESS. This is where you will recieve alerts, notifications and set up admin access to all mailboxes. MUST BE AN INTERNAL ADMIN ADDRESS"
        Write-Host
        Write-Host
        $AcceptedDomains = Get-AcceptedDomain
        $RecipientDomains = $AcceptedDomains.DomainName
        # $AllowedForwardingGroup =  Read-Host "Enter the GUID of the SECURITY GROUP ** IN " QUOTES ** which will allow forwarding to external receipients. (MUST BE ACTIVE IN AAD)"
        # Allowed Forwarding by security groups doesn't work well in practice

        
         # Domains and Senders to whitelist by default. Comma seperated

        $ExcludedDomains = "Umbrellaitgroup.com", "intuit.com"

        $ExcludedSenders = "connect@e.connect.intuit.com", "info@umbrellaitgroup.com", "security@umbrellaitgroup.com"

        $MSPAlertAddress = "Security@umbrellaitgroup.com"



#################################################
## Script Start
#################################################

    # Setup Forwarding and Disable Junk Folder for the Alerting Mailbox
        Write-Host -foregroundcolor $MessageColor "Seting up automatic forwarding from $AlertAddress > to > Security@umbrellaitgroup.com"
        Write-Host
        Write-Host
        Set-Mailbox -Identity $AlertAddress -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $MSPAlertAddress
        Write-Host -ForegroundColor $MessageColor "Forwarding has successfully been configured for the specified mailbox."
        Write-Host
        Write-Host
        get-mailbox -Identity $AlertAddress | Format-List Username,ForwardingSMTPAddress,DeliverToMailboxandForward
        
        Write-Host -foregroundcolor $MessageColor "Disabling Junk Mailbox on $AlertAddress"
        
        Set-MailboxJunkEmailConfiguration -Identity $AlertAddress -Enabled $false -ErrorAction SilentlyContinue
        Write-Host
        Write-Host
        Write-Host -ForegroundColor Green "JunkMailbox has successfully been disabled, this way you will receive all mail from the inbox regardless of mailbox policy."


#################################################
## Anti-Malware
#################################################
        Write-Host
        Write-Host
        Write-Host -foregroundcolor green "Configuring the default Anti-Malware Policy with  [v1.1] settings..."



    ## Default Malware Blacklist
        ## Grab current default File Blacklist and add more entries...
        $FileTypeBlacklist = Get-MalwareFilterPolicy -Identity Default | select -Expand FileTypes
        $FileTypeBlacklist = "ade","adp","app","application","arx","avb","bas","bat","chm","class","cmd","cnv","com","cpl","crt","dll","docm","drv","exe","fxp","gadget","gms","hlp","hta","inf","ink","ins","isp","jar","job","js","jse","lnk","mda","mdb","mde","mdt","mdw","mdz","mpd","msc","msi","msp","mst","nlm","ocx","ops","ovl","paf","pcd","pif","prf","prg","ps1","psd1","psm","psm1","reg","scf","scr","sct","shb","shs","sys","tlb","tsp","url","vb","vbe","vbs","vdl","vxd","wbt","wiz","wsc","wsf","wsh"
            ## Additional filetypes here to blacklist seperated by comma with quotes

        Write-Host -foregroundcolor green "Configuring Anti-Malware Policy [v1.1]"
        Write-Host
        Write-Host
        Write-Host -ForegroundColor Yellow "The Attachment Blacklist contains the following entries. To add more file types, Ctrl-C to cancel and edit the script under the FileTypeBlacklist Variable" 
        Write-Host -ForegroundColor Red $FileTypeBlacklist
        Write-Host
        Write-Host
        Write-Host -foregroundcolor green "Setting up the Default Anti-Malware Policy [v1.1]"


            $MalwarePolicyParam = @{
                'AdminDisplayName' = "AntiMalware Policy [v1.1] Imported via PS";
		        'Action' =  'DeleteAttachmentAndUseCustomAlert';
                'EnableFileFilter' =  $true;
		        'FileTypes' = $FileTypeBlacklist;
                'ZapEnabled' = $true;

		        'CustomAlertText' = "You have received a message that was found to contain malware and protective actions have been automatically taken. If you beleive this is a false positive, please forward this message to Support@umbrellaitgroup.com";
		        'CustomNotifications' = $true;
		        'CustomFromAddress' = $AlertAddress;
		        'CustomFromName' = "ATP Antimalware Scanner";

		        'ExternalSenderAdminAddress' = $AlertAddress;
		        'EnableExternalSenderNotifications' = $true;
		        'EnableExternalSenderAdminNotifications' = $true;
		        'CustomExternalSubject' = "Malware Detected in your Message";
		        'CustomExternalBody' = "We received a message from you that was found to potentially contain malware. Your message was not delivered and protective actions have been automatically taken. It is recomended that you forward this message to your IT Security Department for further investigation.";
		
                'InternalSenderAdminAddress' =  $AlertAddress;
		        'EnableInternalSenderNotifications' =  $true;
		        'EnableInternalSenderAdminNotifications' = $true;
		        'CustomInternalSubject' = "Malware Detected in your Message"
		        'CustomInternalBody' = "A message sent by you was found to potentially contain malware. Your message was NOT delivered and protective actions have been automatically taken. Please reach out to Umbrella IT Group (904) 930-4261 immediatly, and forward this message to Support@Umbrellaitgroup.com";
            }


        #################################################
        ## SET Anti-Malware Default Policy
        #################################################

        Set-MalwareFilterPolicy Default @MalwarePolicyParam -MakeDefault


        Write-Host
        Write-Host
        Write-Host -foregroundcolor yellow "In order to fully set up the default malware policy, you must disable all other rules and policies."

        Get-MalwareFilterRule | Disable-MalwareFilterRule

        Write-Host
        Write-Host
        Write-Host -foregroundcolor green "Anti-Malware Policy [v1.1] has been successfully set."



    ## Anti-Phishing
        ## Write-Host $RecipientDomains  ##(To see all Domains Configured)
 
        $items = Get-Mailbox | select DisplayName,UserPrincipalName
        $combined = $items | ForEach-Object { $_.DisplayName + ';' + $_.UserPrincipalName }
        $TargetUserstoProtect = $combined

        Write-Host 
        Write-Host -foregroundcolor green "Modifying the 'Office365 AntiPhish Default' with Anti-Phish Baseline Policy AntiPhish Policy [v1.1]"

        $PhishPolicyParam=@{

	        ## 'Name' = " AntiPhish Policy [v1.1]"; #(No need for this if modifying the default Policy. Duplicate this for new policies and set a new name.)
	        'AdminDisplayName' = "AntiPhish Policy [v1.1] Imported via PS";
	        'Enabled' = $true;
	        'AuthenticationFailAction' =  'MoveToJmf';
	        'EnableMailboxIntelligence' = $true;
	        'EnableMailboxIntelligenceProtection' = $true;
	        'EnableOrganizationDomainsProtection' = $true;
	        'EnableSimilarDomainsSafetyTips' = $true;
	        'EnableSimilarUsersSafetyTips' = $true;
	        'EnableSpoofIntelligence' = $true;
	        'EnableUnauthenticatedSender' = $true;
	        'EnableUnusualCharactersSafetyTips' = $true;
	        'MailboxIntelligenceProtectionAction' = 'MoveToJmf';
	        'ImpersonationProtectionState' = 'Automatic';
	
            'EnableTargetedDomainsProtection' = $True;
	        'TargetedDomainProtectionAction' =  'Quarantine';
	        'TargetedDomainsToProtect' = $RecipientDomains;

	        'EnableTargetedUserProtection' = $True;
	        'TargetedUserProtectionAction' =  'Quarantine';
	        'TargetedUsersToProtect' = $TargetUserstoProtect;

            'ExcludedDomains' = $ExcludedDomains;
            'ExcludedSenders' = $ExcludedSenders;
	
	        'PhishThresholdLevel' = 2;
                ## 1: Standard: This is the default value. The severity of the action that's taken on the message depends on the degree of confidence that the message is phishing (low, medium, high, or very high confidence). For example, messages that are identified as phishing with a very high degree of confidence have the most severe actions applied, while messages that are identified as phishing with a low degree of confidence have less severe actions applied.
                ## 2: Aggressive: Messages that are identified as phishing with a high degree of confidence are treated as if they were identified with a very high degree of confidence.
                ## 3: More aggressive: Messages that are identified as phishing with a medium or high degree of confidence are treated as if they were identified with a very high degree of confidence.
                ## 4: Most aggressive: Messages that are identified as phishing with a low, medium, or high degree of confidence are treated as if they were identified with a very high degree of confidence.
   
        }

        Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishPolicyParam
        ## New-AntiPhishPolicy @PhishPolicyParam...

        Write-Host
        Write-Host -foregroundcolor yellow "Disabling all the old, non-default phishing rules"

        Get-AntiPhishRule | Disable-AntiPhishRule

        Write-Host
        Write-Host -foregroundcolor green "AntiPhish Policy [v1.1] has been successfully configured"



         

    ## Anti-Spam
        Write-Host -foregroundcolor green "Setting up the new Default Inbound  Anti-Spam Policy [v1.1]"

            $HostedContentPolicyParam = @{
                'AddXHeaderValue' = "M365 ATP Analysis: ";
		        'AdminDisplayName' = "Inbound Anti-Spam Policy [v1.1] configured via M365 PS Scripting Tools";
                'AllowedSenders' = $ExcludedSenders;
                'AllowedSenderDomains' = $ExcludedDomains;
		        'DownloadLink' = $false;
		        'SpamAction' = 'MoveToJMF';
                'HighConfidenceSpamAction' =  'quarantine';
                'PhishSpamAction' = 'quarantine';
                'HighConfidencePhishAction' =  'quarantine';
                'BulkSpamAction' =  'MoveToJMF';
                'BulkThreshold' =  '8';
                'QuarantineRetentionPeriod' = 30;
                'InlineSafetyTipsEnabled' = $true;
                'EnableEndUserSpamNotifications' = $true;
                'EndUserSpamNotificationFrequency' = 1;
		        'EndUserSpamNotificationCustomSubject' = "Daily Email Quarantine Report";
		        'RedirectToRecipients' = $AlertAddress;
		        'ModifySubjectValue' = "PhishSpamAction,HighConfidenceSpamAction,BulkSpamAction,SpamAction";
                'SpamZapEnabled'= $true;
                'PhishZapEnabled' = $true;
                'MarkAsSpamBulkMail' = 'On';
                'IncreaseScoreWithImageLinks' = 'off';
                'IncreaseScoreWithNumericIps' = 'on';
                'IncreaseScoreWithRedirectToOtherPort' = 'on';
                'IncreaseScoreWithBizOrInfoUrls' = 'on';
                'MarkAsSpamEmptyMessages' ='on';
                'MarkAsSpamJavaScriptInHtml' = 'on';
                'MarkAsSpamFramesInHtml' = 'off';
                'MarkAsSpamObjectTagsInHtml' = 'off';
                'MarkAsSpamEmbedTagsInHtml' ='off';
                'MarkAsSpamFormTagsInHtml' = 'off';
                'MarkAsSpamWebBugsInHtml' = 'on';
                'MarkAsSpamSensitiveWordList' = 'off';
                'MarkAsSpamSpfRecordHardFail' = 'on';
                'MarkAsSpamFromAddressAuthFail' = 'on';
                'MarkAsSpamNdrBackscatter' = 'on';
            }

        Set-HostedContentFilterPolicy Default @HostedContentPolicyParam -MakeDefault
        Write-Host 
        Write-Host -foregroundcolor green " Inbound Anti-Spam Policy [v1.1] is deployed and set as Default."
        Write-Host 

            $Answer2 = Read-Host "Do you want to DISABLE (not delete) custom anti-spam rules, so that only  Anti-Spam Policy [v1.1] Apply? This is recommended unless you have other custom rules in use. Type Y or N and press Enter to continue"
                        if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {

                        Get-HostedContentFilterRule | Disable-HostedContentFilterRule
                
                        Write-Host
                        Write-Host -ForegroundColor Yellow "All custom anti-spam rules have been disabled; they have not been deleted"
                        Write-Host 
                        Write-Host -foregroundcolor green " Anti-Spam Policy [v1.1] is set as Default and is the only enforcing Imbound Rule."
                        } else {
                            Write-Host 
                            Write-Host -ForegroundColor Yellow "Custom rules have been left enabled. Please manually verify that the new Default Policy is being used in Protection.Office.com."
                   }

        Write-Host 
        Write-Host 
        Write-Host -foregroundcolor green "Setting up the new Default Inbound/Outbound Anti-Spam Policy [v1.1] + Admin Forwarding Policy"

                $OutboundPolicyForITAdmin = @{
			        'Name' = "IT Admin Allow Outbound Forwarding Policy"
			        'AdminDisplayName' = "Unrestricted Outbound Forwarding Policy from specified mailbox";
			        'AutoForwardingMode' = "On";
                    'RecipientLimitExternalPerHour' = 10000;
                    'RecipientLimitInternalPerHour' = 10000;
                    'RecipientLimitPerDay' = 10000;
                    'ActionWhenThresholdReached' = 'Alert';
			        'BccSuspiciousOutboundMail' = $false
                }
        New-HostedOutboundSpamFilterPolicy @OutboundPolicyForITAdmin


                $OutboundRuleForAdmin=@{
			        'Name' = "IT Admin Allow Outbound Forwarding Rule";
			        'Comments' = "Unrestricted Outbound Forwarding Policy from specified mailbox";
			        'HostedOutboundSpamFilterPolicy' = "IT Admin Allow Outbound Forwarding Policy";
			        'Enabled' = $true;
			        'From' = $AlertAddress;
                    # 'FromMemberOf' = $AllowedForwardingGroup;
			        'Priority' = 0
                }
        New-HostedOutboundSpamFilterRule @OutboundRuleForAdmin


           $AdminIndoundContentPolicyParam = @{
                'Name' = "Unrestricted Content Filter Policy for Admin"
		        'AdminDisplayName' = "Inbound ADMIN Policy [v1.1] configured via M365 PS Scripting Tools";
                'AddXHeaderValue' = "Unrestricted-Admin-Mail: ";
                'RedirectToRecipients' = "security@umbrellaitgroup.com";
		        'DownloadLink' = $false;
		        'SpamAction' = 'AddXHeader';
                'HighConfidenceSpamAction' =  'AddXHeader';
                'PhishSpamAction' = 'AddXHeader';
                'HighConfidencePhishAction' =  'Redirect';
                'BulkSpamAction' =  'AddXHeader';
                'InlineSafetyTipsEnabled' = $true;
		        'ModifySubjectValue' = "PhishSpamAction,HighConfidenceSpamAction,BulkSpamAction,SpamAction";
                'SpamZapEnabled'= $false;
                'PhishZapEnabled' = $false;
                'QuarantineRetentionPeriod' = 30;

                'MarkAsSpamBulkMail' = 'off';
                'IncreaseScoreWithImageLinks' = 'off';
                'IncreaseScoreWithNumericIps' = 'off';
                'IncreaseScoreWithRedirectToOtherPort' = 'off';
                'IncreaseScoreWithBizOrInfoUrls' = 'off';
                'MarkAsSpamEmptyMessages' ='off';
                'MarkAsSpamJavaScriptInHtml' = 'off';
                'MarkAsSpamFramesInHtml' = 'off';
                'MarkAsSpamObjectTagsInHtml' = 'off';
                'MarkAsSpamEmbedTagsInHtml' ='off';
                'MarkAsSpamFormTagsInHtml' = 'off';
                'MarkAsSpamWebBugsInHtml' = 'off';
                'MarkAsSpamSensitiveWordList' = 'off';
                'MarkAsSpamSpfRecordHardFail' = 'off';
                'MarkAsSpamFromAddressAuthFail' = 'off';
                'MarkAsSpamNdrBackscatter' = 'off';
            }
        New-HostedContentFilterPolicy @AdminIndoundContentPolicyParam

        $AdminIndoundContentRuleParam = @{
                'Name' = "Unrestricted Content Filter Rule for Admin"
		        'Comments' = "Inbound ADMIN Rule [v1.1] configured via M365 PS Scripting Tools";
                'HostedContentFilterPolicy' = "Unrestricted Content Filter Policy for Admin";
                'Enabled' = $true;
                'Confirm' = $false;
                'Priority' = "0";
                'SentTo' = $AlertAddress
            }
        New-HostedContentFilterRule @AdminIndoundContentRuleParam


        Write-Host 
        Write-Host -foregroundcolor green "Successfully Set up Policy + Rule for Admin"

                $OutboundPolicyDefault = @{
			        'AdminDisplayName' = "Outbound Anti-Spam Policy [v1.1] configured via M365 PS Scripting Tools";
			        'AutoForwardingMode' = "Off";
                    'RecipientLimitExternalPerHour' = 100;
                    'RecipientLimitInternalPerHour' = 100;
                    'RecipientLimitPerDay' = 500;
                    'ActionWhenThresholdReached' = 'Alert';
			        'BccSuspiciousOutboundMail' = $true;
			        'BccSuspiciousOutboundAdditionalRecipients' = $AlertAddress
                }
        Set-HostedOutboundSpamFilterPolicy Default @OutboundPolicyDefault

        Write-Host    
        Write-Host
        Write-Host -ForegroundColor Green "The admin forwarding and default outbound spam filter have been set to Outbound Anti-Spam Policy [v1.1]"
   
        


       


    ## Safe-Attachments
        Write-Host -foregroundcolor green "Creating the new  Safe Attachments [v1.1] Policy..."
        Write-Host	
        Write-Host -foregroundcolor Yellow "In order to properly set up the new policies, you must remove the old ones."

        Get-SafeAttachmentPolicy | Remove-SafeAttachmentPolicy

        Write-Host 
        Write-Host -foregroundcolor green "Successfully Disabled"


            $SafeAttachmentPolicyParam=@{
               'Name' = "Safe Attachments Policy [v1.1]";
               'AdminDisplayName' = " Safe Attachments Policy [v1.1] configured via M365 PS Scripting Tools";
               'Action' =  "DynamicDelivery";
               ## Action options = Block | Replace | Allow | DynamicDelivery
               'Redirect' = $true;
               'RedirectAddress' = $AlertAddress;
               'ActionOnError' = $true;
               'Enable' = $true
               #'RecommendedPolicyType' = No documentation available
            }

        New-SafeAttachmentPolicy @SafeAttachmentPolicyParam

        Write-Host 
        Write-Host -foregroundcolor green "The new  Safe Attachments Policy [v1.1] is deployed."
        Write-Host 
        Write-Host -foregroundcolor green "Creating the new  Safe Attachments [v1.1] Rule..."
        Write-Host	
        Write-Host -foregroundcolor Yellow "In order to properly set up the new policies, you must remove the old ones."

        Get-SafeAttachmentRule | Disable-SafeAttachmentRule

        Write-Host 
        Write-Host -foregroundcolor green "Successfully Disabled"


            $SafeAttachRuleParam=@{
                'Name' = "Safe Attachments Rule [v1.1]";
	            'SafeAttachmentPolicy' = "Safe Attachments Policy [v1.1]";
		        'Comments' = "Safe Attachments Rule [v1.1] configured via M365 PS Scripting Tools";
	            'RecipientDomainIs' = $RecipientDomains;
                'ExceptIfSentTo' = $AlertAddress;
             #   'ExceptIfRecipientDomainIs' = $ExcludedDomains;
	            'Enabled' = $true;
	            'Priority' = 0
            }

        New-SafeAttachmentRule @SafeAttachRuleParam

        Write-Host 
        Write-Host -foregroundcolor green "The new Safe Attachments Rule [v1.1] is deployed."
        Write-Host 
        Write-Host 
        write-host -foregroundcolor green "Safe Attachments Policy and Rule [v1.1] has been successfully configured."

        


   ## Safe-Links

       $AtpSafeLinksO365Param=@{
               'EnableATPForSPOTeamsODB' =  $true;
               'EnableSafeLinksForO365Clients' = $true;
               'EnableSafeDocs' = $true;
               'AllowSafeDocsOpen' = $false;
               'TrackClicks' = $true;
               'AllowClickThrough' = $false
            }

        Set-AtpPolicyForO365 @AtpSafeLinksO365Param

        write-host -foregroundcolor green "Global Default Safe Links policy has been set."
        Write-Host
        Write-Host -foregroundcolor green "Creating new policy: ' Safe Links Policy [v1.1]'"
        Write-Host	
        Write-Host -foregroundcolor Yellow "In order to properly set up the new policies, you must remove the old ones."

        Get-SafeLinksPolicy | Remove-SafeLinksPolicy

        Write-Host 
        Write-Host -foregroundcolor green "Successfully Disabled"

            $SafeLinksPolicyParam=@{
               'IsEnabled' = $true;
               'Name' = "Safe Links Policy [v1.1]";
               'AdminDisplayName' = "Safe Links Policy [v1.1] configured via M365 PS Scripting Tools";
           #    'EnableSafeLinksForTeams' = $true; Only a part of the TAP Program - License required
               'ScanUrls' = $true;
               'DeliverMessageAfterScan' = $true;
               'EnableForInternalSenders' = $true;
               'DoNotTrackUserClicks' = $false;
               'DoNotAllowClickThrough' =  $true;
               'EnableOrganizationBranding' = $true;
               #'RecommendedPolicyType' = No documentation available
               #'UseTranslatedNotificationText' = No documentation available
            }


        New-SafeLinksPolicy @SafeLinksPolicyParam 

        Write-Host -foregroundcolor Yellow "In order to properly set up the new rules, you must remove the old ones."

        Get-SafeLinksRule | Remove-SafeLinksRule


            $SafeLinksRuleParam = @{
                'Name' = "Safe Links Rule [v1.1]";
	            'Comments' = "Safe Links Rule [v1.1] configured via M365 PS Scripting Tools";
	            'SafeLinksPolicy' = "Safe Links Policy [v1.1]";
	            'RecipientDomainIs' = $RecipientDomains;
                'ExceptIfSentTo' = $AlertAddress;
              #  'ExceptIfRecipientDomainIs' = $ExcludedDomains;
	            'Enabled' = $true;
	            'Priority' = 0
            }

        New-SafeLinksRule @SafeLinksRuleParam


        Write-Host -foregroundcolor green "Safe Links Global Defaults, Policy and Rules [v1.1] has been successfully configured"

    }



    Write-Host
    Write-Host
    Write-Host -ForegroundColor green "This concludes the script for [v1.1] ATP Master Configs"