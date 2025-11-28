############################################################
#  Terraform IaC for Thesis Project
#  - 목적: AWS DynamoDB 테이블(thesis-signups) 자동 생성
#  - IaC(코드 기반 인프라 정의)와 보안 분석(tfsec)을 위한 예시
############################################################

# Terraform 버전 및 Provider 설정
terraform {
  required_version = ">= 1.5.0"     # Terraform 최소 버전
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"            # AWS Provider 버전
    }
  }
}

# AWS 리전 설정 (기본값: us-east-1)
provider "aws" {
  region = var.region
}

# region 변수 정의 (필요시 override 가능)
variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

############################################################
# DynamoDB Table Resource: thesis-signups
# - 회원가입 사용자(Employee / Guest) 데이터 저장용
# - IaC를 통한 테이블 자동 생성
############################################################

# 인프라 설계도 (Infrastruture Blueprint)
resource "aws_dynamodb_table" "signups" {
  name         = "thesis-signups"          # 테이블 이름
  billing_mode = "PAY_PER_REQUEST"         # 온디맨드 과금 (간단하고 무료 티어 포함)

  # 파티션 키 (role) / 정렬 키 (username)
  hash_key  = "role"                       # PK: Employee, Guest 등 역할 구분
  range_key = "username"                   # SK: 사용자명

  # 테이블 속성 정의
  attribute {
    name = "role"
    type = "S"                             # String 타입
  }
  attribute {
    name = "username"
    type = "S"
  }

  ##########################################################
  # 보안 및 복구 설정 (Secure Version)
  # oint_in_time_recovery, server_side_encryption: 이거를 주석처리하면 tfsec 권장 설정 무시(insecure)
  ##########################################################
  
  # 데이터 복구 기능 (Point-In-Time Recovery)
  point_in_time_recovery {
    enabled = true                         # tfsec 권장 설정 
  }

  # 서버사이드 암호화 (SSE)
  server_side_encryption {
    enabled = true                         # tfsec 권장 설정 (기본 KMS 키 사용)
  }

  # 리소스 태그 (관리/식별용)
  tags = {
    Project = "thesis"
    Purpose = "signups"
    Security = "enabled"
  }
}

############################################################
# S3 Bucket: devsecops-thesis-artifacts (reports & charts)
# - 11월 7일: 보안 리포트 저장용 버킷 생성
# - tfsec 테스트용: encryption / versioning / public access
############################################################

resource "aws_s3_bucket" "artifacts" {
  bucket        = "thesis-artifacts-jiyoung-24142816" # 전역 유니크 이름 필요
  force_destroy = true

  tags = {
    Project  = "thesis"
    Purpose  = "artifacts-storage"
    Security = "enabled"
  }
}

# 버전 관리 (권장)
resource "aws_s3_bucket_versioning" "artifacts_versioning" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 서버사이드 암호화 (tfsec 권장 설정)
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts_sse" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 퍼블릭 접근 차단 (tfsec 권장)
resource "aws_s3_bucket_public_access_block" "artifacts_pab" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 출력
output "artifacts_bucket_name" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "S3 bucket name"
}

resource "aws_s3_object" "raw_prefix" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "raw/"
  content = ""    # 0바이트 객체로 프리픽스 고정
}

resource "aws_s3_object" "aggregated_prefix" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "aggregated/"
  content = ""
}

############################################################
# (선택) 비교용 Insecure Version - 보안 설정 미적용
#   → tfsec 실행 시 취약점 탐지용으로 활용
############################################################
/*
resource "aws_dynamodb_table" "signups_insecure" {
  name         = "thesis-signups-insecure"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "role"
  range_key    = "username"

  attribute {
    name = "role"
    type = "S"
  }
  attribute {
    name = "username"
    type = "S"
  }

  # ⚠ 보안 설정 없음 (암호화/복구 비활성)
  # tfsec가 다음과 같은 경고를 표시할 것임:
  # - AWS077: DynamoDB table has no server-side encryption
  # - AWS078: DynamoDB table does not have point-in-time recovery enabled
  tags = {
    Project = "thesis"
    Purpose = "signups_insecure"
    Security = "disabled"
  }
}
*/
