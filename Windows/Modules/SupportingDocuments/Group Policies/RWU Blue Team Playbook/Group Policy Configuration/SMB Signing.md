# Enabling the Microsoft network server: Digitally sign communications (always) setting
1. Open Group Policy Management
2. Right click the domain
3. Click "Create a GPO in this domain, and Link it here..."
4. In the "Name" field, enter: SMB Signing
5. Select the OK button
6. Right click the Group Policy Object that says "SMB Signing"
7. Select the "Edit..." button
8. Expand the following path
	1. Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
9. Find the setting that says "Microsoft network server: Digitally sign communications (always)" and double click it
10. Check off the "Define this policy setting:" checkbox
11. Select the Enabled radio button
12. Select the OK button
13. Select the Yes button on the "Confirm Setting Change" dialog box
# Enabling the Microsoft network client: Digitally sign communications (always) setting
## Prerequisites
At this point, you should have the SMB Signing Group Policy Object created and a previous setting created. If you do not have this, ensure you complete that before moving onto this set of steps
1. Open up the SMB Signing group policy setting
2. Expand the following path
	1.  Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
3. Find the setting that says "Microsoft network server: Digitally sign communications (always)" and double click it
4. Check off the "Define this policy setting:" checkbox
5. Select the Enabled radio button
6. Select the OK button
7. Select the Yes button on the "Confirm Setting Change" dialog box
## Post Configuration Action
