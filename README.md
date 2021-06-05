# ESP32 AWS SigV4

This ESP32 component generates the [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) for use in microcontrollers. There's libraries floating around for SigV4 calculations in C, but they rely on OpenSSL - this component's only dependency is Mbed TLS, which is available both for Arduino and ESP-IDF.

Currently this component only supports generating S3 presigned URLs. These presigned URLs can be used to retrieve OTA updates from S3 directly.
