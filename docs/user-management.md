# User management UI

The UI exposes Bot Users, Web Accounts, and Devices to operator and admin web
accounts. Operators have read-only access; viewer accounts cannot open these
management pages. Admins can create, update, enable/disable, and delete Bot
Users; create local Web Accounts, change their roles, reset passwords, and
disable/delete accounts; and create, reassign, or revoke devices. Creating or
promoting a Bot User to admin requires a Telegram ID.

Bot User deletion uses existing service safeguards and removes associated
peers. Operators can view but not mutate; viewers are denied access. Web
Account self-demotion, self-disablement, self-deletion, and removal or
demotion of the last enabled local admin are blocked. Every mutation form
requires the session CSRF token.
