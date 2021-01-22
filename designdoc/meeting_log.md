## 01/22/2021

Went through the rule doc and some parts of the source code.
- We are supposed to modify the controller parts, and other parts? (I don't remember.)
- Quick notes:
  - 4.6 Message Format
    - If the head is fixed, message body should be protected.
  - Security Requirements (rule doc page 25):
    - Confidentiality
      - Transitions should be encrypted: RSA or AES (mode is important)
    - Integrity and authentication
      - hmac or ...
      - different keys for different SEDs, where to store the keys?
    - Replay protection
      - Sequence number for each pair of SEDs? 
    - SED User code is not secure, and CPU interface is not secure
  - 7.1.2 Reverse Engineering Challenge
    - ch-1 passwd: `firstoneseasy`

