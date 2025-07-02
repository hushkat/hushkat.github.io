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
### Prerequisites for the IAM Privilege Escalation Lab
Base Environment
✅ Kali Linux Virtual Machine
(Recommended: Latest version, fresh install with internet access)
(Note: This tutorial assumes a Kali VM, but any Linux distro with these tools will work)

### Tools Required for This Scenario
1. AWS CLI (to interact with AWS APIs)
2. Git (to clone CloudGoat)
3. Python 3.8+ & Poetry (for CloudGoat dependencies)
4. jq (optional, for parsing JSON outputs)

### Optional: Installing Terraform for Infrastructure-as-Code (IaC) Scenarios
While not required for the current IAM privilege escalation lab, many CloudGoat scenarios leverage Terraform to provision vulnerable AWS resources. Here's how to install it:

Quick Install for Linux (Debian/Ubuntu)
```bash
sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg | \
gpg --dearmor | \
sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt-get install terraform
```
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

## Configuring the CLI
1. Go to cli-user → "Security Credentials" tab → "Create Access Key"
2. Optionally add a description tag
3. Note the Access Key ID and Secret Access Key (or download them)
![AccessKeyCreated](/assets/images/CloudGoat/AccessKeyCreated.png)
4. In your terminal, run:
```bash
aws configure
```
![AWSConfigure](/assets/images/CloudGoat/AWSConfigure.png)
5. Enter the Access Key ID and Secret Access Key when prompted
6. Leave other fields blank by pressing Enter

## Setting Up CloudGoat Using a Script
Create a file setup-cloudgoat.sh with this content:
```bash
#!/bin/bash
set -e
echo "[*] Cloning CloudGoat repository..."
rm -rf cloudgoat
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat

echo "[*] Installing Poetry..."
curl -sSL https://install.python-poetry.org | python3 -

# Export Poetry path
export PATH="$HOME/.local/bin:$PATH"

# Add Poetry to shell config
if [[ "$SHELL" == *zsh ]]; then
    SHELL_RC="$HOME/.zshrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$SHELL_RC"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
    echo "[*] Added Poetry to PATH in $SHELL_RC"
fi

echo "[*] Installing CloudGoat dependencies via Poetry..."
poetry install

echo "[*] Configuring CloudGoat AWS profile..."
if [ ! -f "$HOME/.aws/credentials" ]; then
    echo "AWS credentials not found! Please configure them first."
    echo "Run: aws configure"
    exit 1
fi

poetry run python3 -m cloudgoat.cloudgoat config aws <<< $'y\ndefault'

echo "[*] Setting up IP whitelisting..."
if [ ! -f "cloudgoat/whitelist.txt" ]; then
    echo "[*] Creating whitelist.txt with current IP..."
    poetry run python3 -m cloudgoat.cloudgoat whitelist <<< "y"
else
    echo "[*] whitelist.txt already exists, skipping creation"
fi

echo "[*] Verifying AWS configuration..."
if [ ! -f "cloudgoat/config.yml" ]; then
    echo "[!] Error: config.yml not created!"
    exit 1
fi

echo "[*] Setup complete."
cat <<EOF
✅ CloudGoat Setup Successful!
🧪 To run a scenario:
  cd cloudgoat
  poetry run python3 -m cloudgoat.cloudgoat create iam_privesc_by_rollback --profile default
🧼 To clean up:
  poetry run python3 -m cloudgoat.cloudgoat destroy iam_privesc_by_rollback --profile default
EOF
```
Make it executable and run it:
```bash
chmod +x setup-cloudgoat.sh
./setup-cloudgoat.sh
```

Then execute the scenario:

```bash
cd cloudgoat
poetry run python3 -m cloudgoat.cloudgoat create iam_privesc_by_rollback --profile default
```
Once the scenario is loaded successfully, you expect to see something like this:
![ScenarioLoaded](/assets/images/CloudGoat/ScenarioLoaded.png)