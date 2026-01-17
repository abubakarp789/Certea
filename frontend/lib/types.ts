export interface GenerateKeysRequest {
  passphrase?: string;
  key_size: number;
  response_format?: 'json' | 'zip';
}

export interface GenerateKeysResponse {
  private_key: string;
  public_key: string;
}

export interface SignMessageRequest {
  message: string;
  private_key_pem: string;
  passphrase?: string;
}

export interface SignMessageResponse {
  signature: string;
  timestamp: string;
  message_digest: string;
  padding_scheme: string;
}

export interface VerifyMessageRequest {
  message: string;
  signature: string;
  public_key_pem: string;
}

export interface VerifyMessageResponse {
  is_valid: boolean;
  error_message?: string;
  timestamp: string;
}

export interface SignFileResponse {
  signature: string;
  document_name: string;
  message_digest: string;
}

export interface VerifyFileResponse {
  is_valid: boolean;
  error_message?: string;
  file_digest: string;
}

export interface CreateCAResponse {
  ca_name: string;
  private_key: string;
  public_key: string;
}

export interface SignCertificateResponse {
  subject: string;
  issuer: string;
  serial_number: string;
  validity_period: {
    not_before: string;
    not_after: string;
  };
  public_key_info: string;
  signature: string;
}

export interface VerifyCertificateResponse {
  is_valid: boolean;
  subject?: string;
  issuer?: string;
  error?: string;
}

export interface LogEntry {
  timestamp: string;
  result: boolean;
  message_id: string;
  signature_id: string;
}

export interface Certificate {
  subject: string;
  issuer: string;
  serial_number: string;
  validity_period: {
    not_before: string;
    not_after: string;
  };
  public_key_info: string;
  signature: string;
}

export type ToastType = 'success' | 'error' | 'warning' | 'info';
