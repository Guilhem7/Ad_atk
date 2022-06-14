# Ad_atk
Basic script to try basic attacks on Active Directory
Require either /etc/resolv.conf or a file named dc.txt containing the needed informations
And Require of course impacket

## Script idea
- Parse /etc/resolv.conf to get Domain name, and DC name/ip
- Try anonymous query (via ldap) on the first DC
- Test for zerologon (Cannot exploit it)
- Launch password spray (via ldap) with a predefined user list
- If account found: (or if you know one you cann add it by skipping steps)
    - Try this account on ALL domains computers to see if this user is admin on it
    - Recover domain users (via ldap)
    - Recover Interesting description (containing 'pw','=','pass')
    - Recover Domain Admin
    - Try cve SamAccountName Spoofing (over SAMR) with the account found and Choosing one DA from previous result
- Exit

(The script sam spoof also TRY to remove the computer if it already exist)

```python
python3 ad_try.py
```
