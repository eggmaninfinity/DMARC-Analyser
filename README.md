# What does it do?

This python script loops through DMARC reports in a specified folder to check for SPF and DKIM failures. Any failures are printed on the terminal screen, along with the name of the file, the date of the failure and the IP address of the sender.

## What are DMARC Reports?

DMARC reports help you to see which emails have been sent from your organisation's domain. Monitoring an organisations DMARC reports is crucial for maintaining visibility of email behaviour. For instance: whether your emails are ending up in the reciever's spam/junk folder or being delivered at all. It also protects against a form of cyber criminality known as 'Business Email Compromise', which is when an attacker pretends to send emails from your organisation.

DMARC assesses whether emails have passed two kinds of security checks: SPF and DKIM.

* SPF stands for Sender Poicy Framework, and is essentially a list of IP addresses that are allowed to send emails with an organisations domain name.

* DKIM stands for DomainKeys Identified Mail, and is a hash of the sent email that has been cryptographically signed with the organisations private key - which means it can be decrypted using the organisations public key and then checked against a hash of the file performed by the receiver. Any changes to the email in transit means the hashes won't be the same.

SPF and DKIM verify the technical origin of an email, but they do not automatically verify that the domain in the "From" address (the one the user sees) matches the domain used for SPF/DKIM. DMARC is what links these together. Without this check, a malicious actor could send an email using their own valid SPF/DKIM setup but put your organization’s name in the visible "From" field. DMARC checks that the "From" domain aligns with the domains validated by SPF and DKIM.

DMARC policy i.e. what a receiver should do if an email fails DMARC, is configured in the sending organisations DNS records, along with an email address for receiving the reports. Organizations typically start with a policy of `p=none` to monitor traffic via Aggregate (RUA) reports without blocking mail, and gradually tighten security to `p=quarantine` and finally `p=reject` once they are confident all legitimate mail sources are correctly configured.


A good explanation of DMARC, SPF and DKIM can also be found here: https://dmarcreport.com/blog/spf-vs-dkim-vs-dmarc-difference-explained-2026/
