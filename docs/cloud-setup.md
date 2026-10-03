# Cloud account setup

Notes for whoever provisions a new settlement environment.

## AWS credentials

The release job assumes a role; nobody should be creating long-lived access
keys. If you are following the AWS documentation, the examples there look like
this:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Those are the published example values from the AWS docs, not credentials. Real
values come from the OIDC role the workflow assumes, and never get written to
disk.

## Terraform Cloud

Workspaces are defined in `ops/terraform/`. Run `terraform login` once and the
token lands in `~/.terraform.d/credentials.tfrc.json`, outside the repository.

## Checklist

- [ ] OIDC role created and trusted by the release workflow
- [ ] Settlement SFTP allow-list updated with the NAT egress IPs
- [ ] Bank mTLS certificate uploaded to the cluster
- [ ] Status page DNS pointed at the new load balancer
