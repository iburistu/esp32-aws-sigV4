/*!
*  @file esp32_aws_sigV4.h
*
*  @brief Subroutines to calculate AWS SigV4 signatures
*
*  @author Z. Linkletter
*
*/

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/md.h>

/*!
*   @brief URL encodes a string
*   @param str string to encode
*   @returns pointer to the URL encoded string
*/
char *aws_sigV4_url_encode(char *str);

/*!
*   @brief Converts binary hash to its hex string equivalent
*   @param str binary hash
*   @returns pointer to the hex string
*/
char *aws_sigV4_to_hex_string(char *str);

/*!
*   @brief Creates a signing key. This key is valid for 7 days
*   @param secret_access_key AWS secret access key
*   @param x_amz_date The current UTC date
*   @param aws_region The region that this signing key will be valid for
*   @param aws_service The service that this key is valid to sign for
*   @returns pointer to the signing key
*/
char *aws_sigV4_create_signing_key(char *secret_access_key, char *x_amz_date,
                                   char *aws_region, char *aws_service);

/*!
*   @brief Signs a string with HMAC SHA256
*   @param key Key to use to sign
*   @param key_len Length of the key
*   @param value Value to sign
*   @param value_len Length of value to sign
*   @returns Pointer to the signed result
*/
char *aws_sigV4_sign(char *key, size_t key_len, char *value, size_t value_len);

/*!
*   @brief Generate a presigned URL for S3
*   @param access_key AWS access key
*   @param secret_access_key AWS secret access key
*   @param x_amz_security_token (Optional) Security token from STS
*   @param bucket Bucket that holds the object you'd like to generate the URL for
*   @param object Absolute path of the object to generate the URL for
*   @param aws_region AWS region of the bucket
*   @param x_amz_date Current UTC date
*   @param x_amz_time Current UTC time
*   @param x_amz_expires Expiry time of the link, in minutes
*   @returns Pointer to the presigned URL string
*/
char *aws_sigV4_presign_url(char *access_key, char *secret_access_key,
                            char *x_amz_security_token, char *bucket,
                            char *object, char *aws_region, char *x_amz_date,
                            char *x_amz_time, char *x_amz_expires);

/*!
*   @brief Generate the canonical request of an S3 request
*   @param method Method used to access S3
*   @param canonical_uri Canonical URI of the request
*   @param canonical_query_string Canonical query string of the request
*   @param canonical_headers Canonical headers of the request
*   @param x_amz_signed_headers Signed headers for the request
*   @param hashed_payload Hashed payload of the request
*   @returns Pointer to the canonical request string
*/
char *aws_sigV4_create_canonical_request(char *method,
                                         char *canonical_uri,
                                         char *canonical_query_string,
                                         char *canonical_headers,
                                         char *x_amz_signed_headers,
                                         char *hashed_payload);

/*!
*   @brief Generate the canonical query string of an S3 request
*   @param access_key AWS access key
*   @param x_amz_date Current UTC date
*   @param x_amz_time Current UTC time
*   @param aws_region The region that this request is for
*   @param aws_service The service this request is for
*   @param x_amz_expires Expiry time of the query, in minutes
*   @param x_amz_signed_headers Signed headers for the request
*   @param x_amz_security_token (Optional) Security token from STS
*   @returns Pointer to the canonical query string
*/
char *aws_sigV4_create_canonical_query_string(
    char *access_key, char *x_amz_date, char *x_amz_time, char *aws_region,
    char *aws_service, char *x_amz_expires, char *x_amz_signed_headers,
    char *x_amz_security_token);

/*!
*   @brief Generate the canonical headers string of an S3 request
*   @param host Host of the request
*   @param x_amz_content_sha256 Hashed payload data
*   @param x_amz_date Current UTC date
*   @param x_amz_security_token (Optional) Security token from STS
*   @returns Pointer to the canonical headers string
*/
char *aws_sigV4_create_canonical_headers_string(char *host,
                                                char *x_amz_content_sha256,
                                                char *x_amz_date,
                                                char *x_amz_security_token);

/*!
*   @brief Generate the the string to be signed by the signing key
*   @param x_amz_date Current UTC date
*   @param x_amz_time Current UTC time
*   @param aws_region The region that this request is for
*   @param aws_service The service this request is for
*   @param hashed_canonical_request SHA256 binary hash of the canonical request
*   @returns Pointer to the string to be signed
*/
char *aws_sigV4_create_string_to_sign(char *x_amz_date,
                                      char *x_amz_time,
                                      char *aws_region,
                                      char *aws_service,
                                      char *hashed_canonical_request);