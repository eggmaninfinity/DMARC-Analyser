# What does it do?

This python script loops through DMARC reports in a specified folder to check for SPF and DKIM failures. Any failures are printed on the terminal screen, along with the name of the file, the date of the failure and the IP address of the sender.

## What are DMARC Reports?

DMARC reports help you to see which emails have been sent from your organisation's domain and whether they have passed two kinds of security checks: SPF and DKIM.

SPF stands for Sender Poicy Framework, and is essentially a list of IP addresses that are allowed to send emails with an organisations domain name.

DKIM stands for DomainKeys Identified Mail, and is a hash of the sent email that has been cryptographically signed with the organisations private key - which means it can be decrypted using the organisations public key.

DMARC policy i.e. what a receiver should do if an email fails DMARC, is configured in the sending organisations DNS records, along with an email address for receiving the reports.

Monitoring an organisations DMARC reports is crucial for maintaining visibility of email behaviour. For instance: whether your emails are being delivered, and if not, why not?
It also protects against a form of cyber criminality known as 'Business Email Compromise', where an attacker pretends to send emails from your organisation.


A good explanation of DMARC, SPF and DKIM can also be found here: https://dmarcreport.com/blog/spf-vs-dkim-vs-dmarc-difference-explained-2026/
