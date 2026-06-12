# Multi-resource fixture for taint propagation testing
# Chain: s3_bucket ← lambda ← iam_role (3 hops)

resource "aws_s3_bucket" "data" {
  bucket = "cloudspill-data-bucket"
  acl    = "public-read"
}

resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"

  environment {
    variables = {
      BUCKET = aws_s3_bucket.data.id
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
