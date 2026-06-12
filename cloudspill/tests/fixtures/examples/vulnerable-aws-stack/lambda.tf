# Lambda function that references the tainted S3 bucket
# and runs with an overpermissive IAM role.
# This is the key taint propagation demo:
#   S3 (public) → Lambda (references bucket) → IAM Role (admin access)
resource "aws_lambda_function" "data_processor" {
  function_name = "${var.project}-data-processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 300
  memory_size   = 512

  filename         = "lambda.zip"
  source_code_hash = "placeholder"

  environment {
    variables = {
      UPLOAD_BUCKET = aws_s3_bucket.user_uploads.id
      DATA_BUCKET   = aws_s3_bucket.app_data.id
      DB_HOST       = aws_db_instance.main.endpoint
      ENVIRONMENT   = var.environment
    }
  }

  tags = {
    Name        = "${var.project}-data-processor"
    Environment = var.environment
  }
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.data_processor.function_name
  principal     = "apigateway.amazonaws.com"
}
