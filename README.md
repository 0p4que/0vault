# 0vault
Encrypted password manager with GUI
By 0p4que

**Features:**
- Database encryption
- Easy to navigate GUI
- Password generator
- Logging

**None standard libraries used:**
- pysqlitecipher

**FYI:**
- 0Vault.png must be included in the root folder otherwise it will not run
- To reset the vault delete vault.db and data files

**Description:**

A password manager with a GUI that I made in my spare time to learn more python. Password is encrypted in the datafile with SHA3_256 and pysqlitecipher uses SHA512 which
I would like to change. Planning to add bcrypt instead.
