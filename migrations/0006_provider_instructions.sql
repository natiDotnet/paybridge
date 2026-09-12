-- Platform-managed customer instructions per provider. Merchants add their own
-- payment methods (provider + receiving account) from the portal; the steps
-- shown to customers come from this central config, editable by admins.

CREATE TABLE provider_instructions (
    provider     TEXT PRIMARY KEY,
    instructions TEXT NOT NULL
);

INSERT INTO provider_instructions (provider, instructions) VALUES
('telebirr',
 'Open the Telebirr app and choose "Send Money"
Enter the receiving number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('cbebirr',
 'Open the CBE Birr app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('mpesa',
 'Open the M-Pesa app and choose "Send Money"
Enter the receiving number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('awash',
 'Open the Awash mobile app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference');
