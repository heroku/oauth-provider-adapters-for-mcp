/**
 * OIDC Provider Configuration Schema and Validation
 * Provides Zod-based validation for OIDC provider configurations
 */

import { z } from 'zod';

/**
 * OIDC Provider Metadata schema for validation
 */
const ServerMetadataSchema = z.object({
  issuer: z.string().url('Invalid issuer URL'),
  authorization_endpoint: z.string().url('Invalid authorization endpoint URL'),
  token_endpoint: z.string().url('Invalid token endpoint URL'),
  jwks_uri: z.string().url('Invalid JWKS URI').optional(),
  userinfo_endpoint: z.string().url('Invalid userinfo endpoint URL').optional(),
  scopes_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  response_modes_supported: z.array(z.string()).optional(),
  claims_supported: z.array(z.string()).optional(),
  subject_types_supported: z.array(z.string()).optional(),
  id_token_signing_alg_values_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
});

/**
 * OIDC Provider Configuration Schema
 */
export const OIDCProviderConfigSchema = z
  .object({
    clientId: z.string().min(1, 'clientId is required'),
    clientSecret: z
      .string()
      .min(1, 'clientSecret is required for confidential clients')
      .optional(),
    issuer: z.string().url('Invalid issuer URL').optional(),
    serverMetadata: ServerMetadataSchema.optional(),
    scopes: z.array(z.string()).default(['openid', 'profile', 'email']),
    additionalParameters: z.record(z.string(), z.string()).optional(),
    timeouts: z
      .object({
        connect: z
          .number()
          .int()
          .positive('Connect timeout must be a positive integer')
          .optional(),
        response: z
          .number()
          .int()
          .positive('Response timeout must be a positive integer')
          .optional(),
      })
      .optional(),
    // Base OAuth fields
    redirectUri: z.string().url('Invalid redirect URI').optional(),
    // OIDC-specific fields
    storageHook: z.any().optional(), // PKCEStorageHook interface - using any for simplicity
    pkceStateExpirationSeconds: z
      .number()
      .int()
      .positive('PKCE state expiration must be a positive integer')
      .optional(),
  })
  .refine((v) => Boolean(v.issuer) !== Boolean(v.serverMetadata), {
    message: 'Provide exactly one of `issuer` or `serverMetadata`',
    path: ['issuer', 'serverMetadata'],
  });

export type OIDCProviderConfig = z.infer<typeof OIDCProviderConfigSchema>;

/**
 * Validate OIDC provider configuration
 * @param config - Configuration object to validate
 * @returns Validated configuration
 * @throws ZodError with detailed validation messages
 */
export function validate(config: unknown): OIDCProviderConfig {
  return OIDCProviderConfigSchema.parse(config);
}

/**
 * Safe validation that returns validation result instead of throwing
 * @param config - Configuration object to validate
 * @returns Validation result with success/error information
 */
export function safeValidate(config: unknown): {
  success: boolean;
  data?: OIDCProviderConfig;
  error?: z.ZodError;
} {
  const result = OIDCProviderConfigSchema.safeParse(config);
  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  } else {
    return {
      success: false,
      error: result.error,
    };
  }
}
