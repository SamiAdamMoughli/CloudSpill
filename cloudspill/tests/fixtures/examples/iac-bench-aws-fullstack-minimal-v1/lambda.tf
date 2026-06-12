# Utility Lambda used for asynchronous background work

data "archive_file" "utility_lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/utility_lambda.zip"

  source {
    content = <<-PY
      import json

      def handler(event, context):
          return {
              "statusCode": 200,
              "body": json.dumps({"message": "ok"})
          }
    PY
    filename = "lambda_function.py"
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-utility"
  retention_in_days = 14
}

resource "aws_lambda_function" "utility" {
  function_name = "${local.name_prefix}-utility"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "lambda_function.handler"
  runtime       = "python3.11"

  filename         = data.archive_file.utility_lambda_zip.output_path
  source_code_hash = data.archive_file.utility_lambda_zip.output_base64sha256

  timeout     = 30
  memory_size = 256

  vpc_config {
    subnet_ids         = aws_subnet.private_app[*].id
    security_group_ids = [aws_security_group.app.id]
  }

  environment {
    variables = {
      THIRD_PARTY_API_KEY = "sk_live_51J2xExampleHardcodedKey000000000000"
      DB_PASSWORD         = "ProdDBPassword!234"
      SUPPORT_WEBHOOK     = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}