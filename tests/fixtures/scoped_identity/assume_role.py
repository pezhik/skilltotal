"""Sanitized fixture: a component that authenticates via a scoped, short-lived assumed identity.

Exercises ST-AUTH-SCOPED (scoped_identity): an STS AssumeRole for temporary, narrowly-scoped
credentials. No secrets; ARNs are example placeholders.
"""

import boto3


def scoped_client(role_arn: str = "arn:aws:iam::000000000000:role/example-readonly"):
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="skilltotal-example")["Credentials"]
    return boto3.client(
        "s3",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],  # short-lived, scoped to the assumed role
    )
