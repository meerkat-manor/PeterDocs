# Design

## Objective

The objective is to provide a simple capability to create a secure
archive file containiung documents to be restored and reconciled at the destination.

The design artefacts must provide all the tools required to pack,
secure, unpack and reconcile the restored/cloned documents.

## Technology

PeterDocs is written as a PowerShell module and uses the 7ZIP and AWS modules.

The AWS module is only used if you are transferring to AWS S3 bucket or compatible destination.
