Playing with libsodium libary to decrypt files encrypted with rclone.
you need to provide the password and salt (which are obscured in rclone.conf).

example : sodium mypassword mysalt myfile.ext.bin

will compile for both windows and linux (fpc 3.0.0+)

Reminder : you can reveal (i.e obtain clear text) your password/salt with the below command line
rclone reveal password (from rclone.conf) 
