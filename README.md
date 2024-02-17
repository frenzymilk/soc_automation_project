# Soc Deployment
This project will deploy a SOC platform using Terraform and Github Actions. The infrastructure is comprised of 3 instances, one for Wazuh, a SIEM and XDR tool, one for TheHive, a tool allowing to provide Incident Response Capabilities, and the last one for an endpoint that will be your target.
In addition to the Wazuh agent, the target instance also uses Sysmon for Linux for endpoint monitoring.

## Deployment

You can deploy this infrastructure by going to Github Actions, choosing the SOC deployment workflow with the **Deploy** option.
You can verify the stqtus of the deployment for each instqnce by accessing the `/var/log/cloud-init.log` file. 
You can access the Wazuh and The Hive dashboards using their IP addresses, do not forget to use the port **9000** for The Hive.
In this deployment, Wazuh and the Hive are integrated, meaning that you can directly create cases in The Hive for alerts received in Wazuh.

## Disclaimer

This deployment will incur charges on your AWS account. It is because Wazuh and The Hive require more capacity than the one provided by instances available in free Tier. 
The target instance is deployed using free Tier.

## Secrets configuration

You should provide the following secrets in your Github project settings for the Github Actions workflow:
- Credentials with administrative access to your AWS account (should be already created in your AWS account)
  - `AWS_ACCESS_KEY`
  - `AWS_SECRET_ACCESS_KEY`
- The name of the key to access your AWS instances via SSH (should be already created in your AWS account)
  - `AWS_KEY_NAME`
- The url of the AWS S3 bucket to store the Terraform state
  - `S3_BUCKET`
- Your public adress to configure the security groups so that your instances are only accessible through your address
  - `MY_IP`
- The usernames and passwords for the users created in theHive
  
First, the values for the default admin user, which will be used to create your first organisation and its users
  - `DEFAULT_THEHIVE_PASSWORD`
  - `DEFAULT_THEHIVE_USER`
    
Second, the values for your organisation users:
  - `MYORG_THEHIVE_USER_ADMIN_PASSWORD`
  - `MYORG_THEHIVE_USER_ANALYST_PASSWORD`
