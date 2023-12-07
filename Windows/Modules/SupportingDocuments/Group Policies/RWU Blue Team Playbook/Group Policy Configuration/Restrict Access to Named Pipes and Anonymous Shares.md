# Enabling the Network access: Restrict anonymous access to Named Pipes and Shares setting
## Notes
1. This setting can be applied to Windows 10 and Windows Server
## Steps
1. Open Group Policy Management
2. Click "Create a GPO in this domain, and Link it here..."
3. In the "Name" field, enter: Restrict Access to Named Pipes and Anonymous Shares
4. Expand the following path: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
5. Find the option that is called "Network Access: Restrict anonymous access to Named Pipes and Shares" and double click it
6. Check off "Define this policy setting"
7. Select Enabled