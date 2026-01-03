# smtpd-filter-addheader

smtpd-filter to add email message header lines

smtpd-filter-addheader modifies all filtered messages by adding the headers
provided as command line arguments.
Header arguments are formatted as KEY=VALUE
At least one header must be provided

Usage:
  smtpd-filter-addheader HEADER [HEADER...] [flags]
