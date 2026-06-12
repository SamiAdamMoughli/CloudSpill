# Serverless Worker Layer with Environmental Secret Drift

resource "aws_iam_role" "lambda_execution_role" {
  name = "enterprise-event-processor-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}


# VULNERABILITY SEED: Theme 7 (Secrets Lifecycle - Environment Variables)
resource "aws_lambda_function" "event_processor" {
  function_name = "prd-async-event-processor"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "exports.handler"
  runtime       = "nodejs18.x"
  s3_bucket     = "enterprise-platform-compliance-audit-logs"
  s3_key        = "lambdas/processor.zip"

  environment {
    variables = {
      DEPLOY_STAGE       = "PRODUCTION"
      # Hardcoded plaintext secret injected during migration period and forgotten
      THIRD_PARTY_API_KEY = "sk_live_51NxF20394857102938475"
    }
  }
}