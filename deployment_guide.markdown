# Project Bedrock Deployment & Architecture Guide

## Architecture Overview
The Project Bedrock infrastructure is deployed in AWS us-west-2 region using Terraform. The architecture consists of:
- A VPC with public and private subnets across two availability zones
- An EKS cluster with managed node groups
- Managed AWS services (RDS PostgreSQL, RDS MySQL, DynamoDB) for persistence
- Application Load Balancer with SSL termination
- Route 53 domain configuration
- GitHub Actions for CI/CD automation

## Accessing the Application
1. The retail store application is accessible via: `https://retail.example.com`
2. The UI service is exposed through an ALB with an SSL certificate from AWS ACM
3. DNS is configured in Route 53 to point to the ALB

## Developer Access Instructions
1. Create access keys for the `bedrock-developer` IAM user through AWS Console
2. Configure AWS CLI:
```bash
aws configure
# Enter Access Key ID and Secret Access Key
# Set region to us-west-2
```
3. Get kubeconfig:
```bash
aws eks update-kubeconfig --region us-west-2 --name bedrock-cluster
```
4. Verify access:
```bash
kubectl get pods
kubectl describe service retail-store-ui
```

## Bonus Objectives Implementation
1. **Managed Persistence Layer**:
   - RDS PostgreSQL instance for orders service
   - RDS MySQL instance for catalog service
   - DynamoDB table for carts service
   - Credentials stored in Kubernetes Secrets
   - ConfigMap updated with managed service endpoints

2. **Advanced Networking & Security**:
   - AWS Load Balancer Controller installed in EKS
   - Ingress resource created for ui service
   - Route 53 configured with retail.example.com (placeholder domain)
   - SSL certificate provisioned via ACM and attached to ALB
   - HTTPS enforced for all external traffic

## Git Repository
- Repository: https://github.com/innovatemart/bedrock-project
- Contains Terraform code, Kubernetes manifests, and GitHub Actions workflow
- README provides detailed setup instructions