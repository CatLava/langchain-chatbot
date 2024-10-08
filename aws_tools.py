import boto3
import os
from dotenv import load_dotenv
from typing import Annotated, Literal, TypedDict
from langchain_core.tools import tool
from botocore.exceptions import ClientError


# Load .env file
load_dotenv()

AWS_API_KEY = os.getenv("AWS_ACCOUNT_ID")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
REGION = os.getenv("REGION", "us-east-1")

ec2 = boto3.client(
    "ec2",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION,
)
s3_client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION,
)
iam_client = boto3.client(
    "iam",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION,
)


@tool
def get_aws_account_info():
    """
    Returns the AWS account ID and Region that the user is interested in

    Returns:
        A string representing the current AWS account id and Region that queries will run in
    """
    AWS_ACCOUNT_ID = AWS_API_KEY
    REGION = os.getenv("REGION", "us-east-1")
    return (AWS_ACCOUNT_ID, REGION)


@tool
def list_aws_s3_buckets() -> str:
    """
    Lists all AWS S3 buckets in the account.

    Returns:
        str: A JSON string representing a list of bucket names.
    """
    response = s3_client.list_buckets()
    buckets = [bucket["Name"] for bucket in response["Buckets"]]
    return str(buckets)

@tool
def is_aws_s3_bucket_public(
    bucket_name: Annotated[str, "Get if an S3 bucket is public or not"]
) -> str:
    """
    inspects if aws s3 bucket is public or not 

    Returns:
        bool whether bucket is public or not
    """
    
    # Check Bucket Policy
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        if policy:
            if 'Public' in policy['Policy']:
                return True
    except:
        pass  # If there's no policy or an error, continue checking

    # Check Bucket ACL
    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    for grant in acl['Grants']:
        grantee = grant.get('Grantee', {})
        if grantee.get('Type') == 'Group' and grantee.get('URI') in [
            'http://acs.amazonaws.com/groups/global/AllUsers',
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        ]:
            if grant['Permission'] in ['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP']:
                return True

    # Check Object Public Access
    public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
    if 'PublicAccessBlockConfiguration' in public_access_block:
        pabc = public_access_block['PublicAccessBlockConfiguration']
        if pabc.get('BlockPublicAcls') == False or \
           pabc.get('IgnorePublicAcls') == False or \
           pabc.get('BlockPublicPolicy') == False or \
           pabc.get('RestrictPublicBuckets') == False:
            return True

    return False

@tool
def list_aws_s3_bucket_objects(
    bucket_name: Annotated[str, "From aws S3 bucket name, list all the objects"]
) -> str:
    """
    from a bucket name will list out all the objects 

    Returns:
        list of all the bucket objects
    """
    
    # Check Bucket Policy
    paginator = s3_client.get_paginator('list_objects_v2')
    
    # Page iterator that yields results up to 1000 keys at a time
    page_iterator = paginator.paginate(Bucket=bucket_name)
    
    all_objects = []
    
    for page in page_iterator:
        # Append all keys from the current page to the list
        all_objects.extend(obj['Key'] for obj in page.get('Contents', []))
    
    return all_objects

@tool
def list_aws_iam_users():
    # query: Annotated[str, "Basic query to get AWS user IAM info from the account"]

    """
    Basic query to get AWS user IAM info from the account, this will list all users

    Returns:
        A list of dictionaries that returns various user information for AWS IAM
    """

    users = []
    paginator = iam_client.get_paginator("list_users")
    for response in paginator.paginate():
        for user in response["Users"]:
            users.append(
                {
                    "User Name": user["UserName"],
                    "User ID": user["UserId"],
                    "Arn": user["Arn"],
                    "Create Date": user["CreateDate"].isoformat(),
                }
            )

    return users


@tool
def get_aws_iam_user_permissions(
    user_name: Annotated[
        str, "Basic query to get a specific AWS IAM user permissions from the account"
    ]
):
    """
    Returns the permissions attached for a user

    Returns:
        A list of dictionaries that returns various user information for AWS IAM
    """

    try:
        # Get user information including groups
        user_response = iam_client.get_user(UserName=user_name)
        user = user_response["User"]
        user_groups = [
            group["GroupName"]
            for group in iam_client.list_groups_for_user(UserName=user_name)["Groups"]
        ]

        # Fetch attached managed policies for the user
        user_policies = iam_client.list_attached_user_policies(UserName=user_name)

        # Fetch inline policies for the user
        inline_policies = iam_client.list_user_policies(UserName=user_name)

        # For each group, fetch the policies
        group_policies = []
        for group in user_groups:
            group_policies.extend(
                iam_client.list_attached_group_policies(GroupName=group)[
                    "AttachedPolicies"
                ]
            )
            group_policies.extend(
                [
                    {"PolicyName": policy}
                    for policy in iam_client.list_group_policies(GroupName=group)[
                        "PolicyNames"
                    ]
                ]
            )

        # Fetch policy documents for all policies
        all_policies = []
        for policy in user_policies["AttachedPolicies"]:
            try:
                policy_doc = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                version = iam_client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_doc["Policy"]["DefaultVersionId"],
                )
                all_policies.append(version["PolicyVersion"]["Document"])
            except ClientError as e:
                print(f"Error fetching policy {policy['PolicyName']}: {e}")

        for policy in inline_policies["PolicyNames"]:
            try:
                policy_doc = iam_client.get_user_policy(
                    UserName=user_name, PolicyName=policy
                )
                all_policies.append(policy_doc["PolicyDocument"])
            except ClientError as e:
                print(f"Error fetching inline policy {policy}: {e}")

        for policy in group_policies:
            try:
                if "PolicyArn" in policy:
                    policy_doc = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                    version = iam_client.get_policy_version(
                        PolicyArn=policy["PolicyArn"],
                        VersionId=policy_doc["Policy"]["DefaultVersionId"],
                    )
                    all_policies.append(version["PolicyVersion"]["Document"])
                elif "PolicyName" in policy:
                    # Assuming groups can have inline policies too
                    group_name = next(
                        g
                        for g in user_groups
                        if policy["PolicyName"]
                        in [p["PolicyName"] for p in group_policies if "PolicyArn" in p]
                    )
                    policy_doc = iam_client.get_group_policy(
                        GroupName=group_name, PolicyName=policy["PolicyName"]
                    )
                    all_policies.append(policy_doc["PolicyDocument"])
            except ClientError as e:
                print(
                    f"Error fetching policy {policy['PolicyName']} from group {group_name}: {e}"
                )

        return all_policies, user_groups

    except ClientError as e:
        print(f"Error getting user info: {e}")
        return None, None


@tool
def get_ec2_instances() -> str:
    """
    Retrieves a list of EC2 instances with their basic details.

    Returns:
        str: A JSON string representing a list of dictionaries, each containing EC2 instance details.
    """
    response = ec2.describe_instances()
    instances = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(
                {
                    "InstanceId": instance["InstanceId"],
                    "InstanceType": instance["InstanceType"],
                    "State": instance["State"]["Name"],
                    "PublicIpAddress": instance.get("PublicIpAddress", "N/A"),
                    "KeyName": instance.get("KeyName", "N/A"),
                    "LaunchTime": instance["LaunchTime"].isoformat(),
                }
            )

    return str(instances)
