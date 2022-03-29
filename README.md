# Ad_atk
Basic script to try basic attacks on Active Directory

# Script idea
- Parse /etc/resolv.conf to get Domain name, and DC name/ip
- Try anonymous query (via ldap) on the first DC
- Test for zerologon (Cannot exploit it)
- Launch password spray (via ldap) with a predefined user list
- If account found:
    - Recover domain users (via ldap)
    - Recover Interesting description (containing 'pw','=','pass')
    - Recover Domain Admin
    - Try cve SamAccount Spoofing (over SAMR) with the account found and Choosing one DA from previous result
- Exit
