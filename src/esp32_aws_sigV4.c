#include "esp_aws_sigV4.h"

/*!
*   @brief Compare two strings
*   @param a Pointer to first string
*   @param b Pointer to second string
*   @returns string which is less
*/
static int pstrcmp(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/*!
*   @brief Generate full string with delimiter from array of strings
*   @param arr Array of strings to join
*   @param count Number of strings to join
*   @param delimiter Character to join strings on
*   @param sort Sort the strings before joining?
*   @returns pointer to the joined
*/
static char *string_gen(char **arr, int count, char deliminer, int sort)
{
    int str_len = 0;
    for (int n = 0; n < count; n++)
    {
        str_len += strlen(arr[n]);
    }
    char *string = malloc((str_len + (count)) * sizeof(char));

    if (sort)
        qsort(arr, count, sizeof(arr[0]), pstrcmp);

    int offset = 0;
    for (int n = 1; n < count; n++)
    {
        sprintf(string + offset, "%s%c", arr[n - 1], deliminer);
        offset += strlen(arr[n - 1]) + 1;
    }

    sprintf(string + offset, "%s", arr[count - 1]);

    return string;
}

char *aws_sigV4_url_encode(char *str)
{
    // SigV4 requires uppercase hex
    static char hex[] = "0123456789ABCDEF";
    char *pstr = str, *buf = malloc((strlen(str) * 3 + 1) * sizeof(char)),
         *pbuf = buf;
    while (*pstr)
    {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' ||
            *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
            *pbuf++ = '+';
        else
            *pbuf++ = '%', *pbuf++ = hex[(*pstr >> 4) & 15],
            *pbuf++ = hex[(*pstr & 15) & 15];
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

char *aws_sigV4_to_hex_string(char *str)
{
    char *hex = malloc(65 * sizeof(char));
    for (int i = 0; i < 32; i++)
    {
        sprintf(hex + (i * 2), "%02x", (unsigned int)str[i] & 0xFF);
    }
    hex[65] = '\0';
    return hex;
}

char *aws_sigV4_create_signing_key(char *secret_access_key, char *x_amz_date,
                                   char *aws_region, char *aws_service)
{
    char *AWS4;
    size_t AWS4_len = asprintf(&AWS4, "AWS4%s", secret_access_key);

    char *kSigning = malloc(32 * sizeof(char));
    kSigning = aws_sigV4_sign(aws_sigV4_sign(aws_sigV4_sign(aws_sigV4_sign(AWS4, AWS4_len, x_amz_date, strlen(x_amz_date)), 32, aws_region, strlen(aws_region)), 32, aws_service, strlen(aws_service)), 32, "aws4_request", strlen("aws4_request"));

    return kSigning;
}

char *aws_sigV4_sign(char *key, size_t key_len, char *value, size_t value_len)
{
    char *signature = malloc(32 * sizeof(char));
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    (unsigned char *)key, key_len, (unsigned char *)value,
                    value_len, (unsigned char *)signature);
    free(key);
    return signature;
}

char *aws_sigV4_create_canonical_request(char *method, char *canonical_uri,
                                         char *canonical_query_string,
                                         char *canonical_headers,
                                         char *x_amz_signed_headers,
                                         char *hashed_payload)
{
    char *canonical_request;
    asprintf(&canonical_request, "%s\n%s\n%s\n%s\n\n%s\n%s", method,
             canonical_uri, canonical_query_string, canonical_headers,
             x_amz_signed_headers, hashed_payload);

    char *hash = malloc(32 * sizeof(char));
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (unsigned char *)canonical_request, strlen(canonical_request),
               (unsigned char *)hash);

    free(canonical_request);

    return hash;
}

char *aws_sigV4_create_string_to_sign(char *x_amz_date, char *x_amz_time,
                                      char *aws_region, char *aws_service,
                                      char *hashed_canonical_request)
{
    char *string_to_sign;
    asprintf(&string_to_sign, "AWS4-HMAC-SHA256\n%sT%sZ\n%s/%s/%s/aws4_request\n%s",
             x_amz_date, x_amz_time, x_amz_date, aws_region, aws_service,
             hashed_canonical_request);

    return string_to_sign;
}

char *aws_sigV4_create_canonical_query_string(
    char *access_key, char *x_amz_date, char *x_amz_time, char *aws_region,
    char *aws_service, char *x_amz_expires, char *x_amz_signed_headers,
    char *x_amz_security_token)
{
    int num_params = 5;

    if (strlen(x_amz_security_token) != 0)
        num_params++;

    char *queries[5] = {"X-Amz-Algorithm=AWS4-HMAC-SHA256"};

    char *credential;
    size_t credential_length =
        asprintf(&credential, "%s/%s/%s/%s/aws4_request", access_key,
                 x_amz_date, aws_region, aws_service);
    char *URL_credential = malloc(credential_length * 3 * sizeof(char));
    URL_credential = aws_sigV4_url_encode(credential);

    free(credential);

    char *x_amz_credential;
    asprintf(&x_amz_credential, "X-Amz-Credential=%s", URL_credential);

    queries[1] = x_amz_credential;

    char *x_amz_datetime_string;
    asprintf(&x_amz_datetime_string, "X-Amz-Date=%sT%sZ", x_amz_date, x_amz_time);

    queries[2] = x_amz_datetime_string;

    char *x_amz_expires_string;
    asprintf(&x_amz_expires_string, "X-Amz-Expires=%s", x_amz_expires);

    queries[3] = x_amz_expires_string;

    char *x_amz_security_token_string;
    if (strlen(x_amz_security_token) != 0)
    {
        char *URL_security_token = aws_sigV4_url_encode(x_amz_security_token);

        asprintf(&x_amz_security_token_string, "X-Amz-Security-Token=%s",
                 URL_security_token);

        queries[4] = x_amz_security_token_string;
        free(URL_security_token);
    }

    char *x_amz_signed_headers_string;
    asprintf(&x_amz_signed_headers_string, "X-Amz-SignedHeaders=%s",
             x_amz_signed_headers);

    // The signed headers query parameter must be last
    // Offset by one if the security token is present
    queries[(strlen(x_amz_security_token) != 0) ? 5 : 4] = x_amz_signed_headers_string;

    char *query_string = string_gen(queries, num_params, '&', 0);

    free(URL_credential);
    free(x_amz_credential);
    free(x_amz_expires_string);
    free(x_amz_signed_headers_string);
    free(x_amz_datetime_string);

    if (strlen(x_amz_security_token) != 0)
        free(x_amz_security_token_string);

    return query_string;
}

char *aws_sigV4_create_canonical_headers_string(char *host,
                                                char *x_amz_content_sha256,
                                                char *x_amz_date,
                                                char *x_amz_security_token)
{
    char *amz_host;
    char *content_sha256;
    char *amz_date;
    char *amz_security_token;

    int num_headers = 1;

    char *headers[4];

    asprintf(&amz_host, "host:%s", host);
    headers[0] = amz_host;

    if (strlen(x_amz_content_sha256) != 0)
    {
        asprintf(&content_sha256, "x-amz-content-sha256:%s", x_amz_content_sha256);
        headers[num_headers] = content_sha256;
        num_headers++;
    }
    if (strlen(x_amz_date) != 0)
    {
        asprintf(&amz_date, "x-amz-date:%s", x_amz_date);
        headers[num_headers] = amz_date;
        num_headers++;
    }
    if (strlen(x_amz_security_token) != 0)
    {
        asprintf(&amz_security_token, "x-amz-security-token:%s",
                 x_amz_security_token);
        headers[num_headers] = amz_security_token;
        num_headers++;
    }
    char *str = string_gen(headers, num_headers, '\n', 1);

    free(amz_host);
    if (strlen(x_amz_content_sha256) != 0)
        free(content_sha256);
    if (strlen(x_amz_date) != 0)
        free(amz_date);
    if (strlen(x_amz_security_token) != 0)
        free(amz_security_token);

    return str;
}

char *aws_sigV4_presign_url(char *access_key, char *secret_access_key,
                            char *x_amz_security_token, char *bucket,
                            char *object, char *aws_region, char *x_amz_date,
                            char *x_amz_time, char *x_amz_expires

)
{
    char *signing_key = aws_sigV4_create_signing_key(
        secret_access_key, x_amz_date, aws_region, "s3");

    char *query_string = aws_sigV4_create_canonical_query_string(
        access_key, x_amz_date, x_amz_time, aws_region, "s3", x_amz_expires,
        "host", x_amz_security_token);

    char *host;
    asprintf(&host, "%s.s3.amazonaws.com", bucket);

    char *canonical_headers = aws_sigV4_create_canonical_headers_string(host, "", "", "");

    char *canonical_request_hash = aws_sigV4_create_canonical_request(
        "GET", object, query_string, canonical_headers, "host", "UNSIGNED-PAYLOAD");

    char *hash_hex = aws_sigV4_to_hex_string(canonical_request_hash);

    char *string_to_sign = aws_sigV4_create_string_to_sign(
        x_amz_date, x_amz_time, aws_region, "s3", hash_hex);

    char *signature =
        aws_sigV4_sign(signing_key, 32, string_to_sign, strlen(string_to_sign));

    char *signature_hex = aws_sigV4_to_hex_string(signature);

    char *presigned_url;

    asprintf(&presigned_url,
             "https://%s.s3.amazonaws.com%s?%s&X-Amz-Signature=%s", bucket,
             object, query_string, signature_hex);

    free(host);
    free(query_string);
    free(canonical_headers);
    free(canonical_request_hash);
    free(hash_hex);
    free(string_to_sign);
    free(signature);
    free(signature_hex);

    return presigned_url;
}
