from engine.vars import valid_aws_regions

def validate_aws_region(aws_region):
    return aws_region in valid_aws_regions