---
title: "The Silent Threat in Your AWS Environment: IAM Privilege Escalation via Policy Rollback"
date: 2025-06-30 01:09:33 +0300
author: [hushkat]
description: IAM Privilege Escalation via Policy Rollback
image: /assets/images/CloudGoat/CloudGoat.png
categories: [AWS, IAM, PRIVILEGE ESCALATION, Cloudgoat]
tags:  [AWS, IAM, PRIVILEGE ESCALATION, Cloudgoat]
---

## ⚠️ Important Disclaimer
> This tutorial is for educational purposes only. All AWS access keys, credentials, and ARNs shown in screenshots or examples:
> 🔒 Were immediately deactivated after this demonstration.
> 🚫 Should never be used to access any AWS resources.
> ⚠️ Are from intentionally vulnerable lab environments (CloudGoat) and not real systems.


## Ethical Use Notice:
> This content demonstrates defensive security research with proper authorization.
> Never test security vulnerabilities against systems you don’t own or have explicit permission to assess.
> Always follow your organization’s cloud security policies and AWS’s Acceptable Use Policy.
> Protect your keys like passwords—exposing them risks account compromise.

## The Danger Lurking in Your Policy History

Imagine this: You've diligently followed security best practices, carefully restricting IAM permissions. Your policies are airtight. Your users have least privilege access. But hidden in your AWS environment, a time bomb ticks - and it's called **Policy Version Rollback**.

In this hands-on walkthrough, we'll explore how attackers can exploit an often-overlooked AWS feature to transform a low-privilege user into a full administrator. This isn't a theoretical vulnerability - it's a real-world risk that stems from how AWS IAM policy versioning works.

## Why This Should Keep You Awake at Night

- **Stealthy**: Leaves no trace in CloudTrail as "SetDefaultPolicyVersion" events
- **Common**: Many organizations forget to clean up old policy versions
- **Powerful**: Can elevate to admin in seconds with the right conditions
- **Overlooked**: Rarely checked in standard security audits

Here is a simple exploitation route that we are going to take in this walkthrough:
![Exploitation_Route](/assets/images/CloudGoat/ExploitationRoute.png)

However, before we do that, let's setup our environment:

## Lab Setup: Preparing Our Environment

### Installing and Configuring the AWS CLI

1. Visit the [AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#getting-started-install-instructions) from [aws.amazon.com/cli](https://aws.amazon.com/cli)
2. Run these commands to install the AWS CLI on your Kali VM:
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

Here is what a successful Installation looks like, verifying with commands like: 
```bash
aws –version or
which aws
```
![SuccessfullyInstalledCLI](/assets/images/CloudGoat/AWSCLI_Installed.png)

### Creating a CLI User
1. Log into the AWS Console
2. Search for and open IAM
3. Click "Users" → "Create user"
![IAM_Console](/assets/images/CloudGoat/IAM_Console.png)
4. Set username as cli-user and proceed
5. Set permissions with Administrator Access
![SettingUserPermissions](/assets/images/CloudGoat/SettingUserPermissions.png)
6. Review and create the user

**Notice that we gave the user Administrator Access and then click on next to proceed to the review page.**
 
On the last page, we can go ahead and review our configurations and just click on create user once we have confirmed everything is set. Once the user has been created successfully, we can click on their username from the list of IAM users from our console, for further configs. 

**It’s important to note that, we know that the user has successfully been created when we see the green notification at the top of the console page.**
